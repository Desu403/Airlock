//! airlock desktop app. The webview never sees document bytes: it gets PNGs
//! encoded here from validated pixels, numbers, and sanitised text.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use airlock_core::live::LiveSession;
use airlock_core::proto::MAX_DOC_BYTES;
use airlock_core::{analysis, report, text};
use serde::Serialize;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tauri::ipc::Response;
use tauri::{Emitter, Manager, State};
use tauri_plugin_dialog::DialogExt;

struct Doc {
    session: LiveSession,
}

#[derive(Default)]
struct AppState {
    doc: Arc<Mutex<Option<Doc>>>,
    initial: Mutex<Option<PathBuf>>,
    /// Pixels only: no document text leaves the VM (no text layer, no Text panel).
    pixels_only: Arc<AtomicBool>,
    /// The last file chosen, even if it could not be displayed: it can
    /// still be analyzed (e.g. an Excel add-in has nothing to show).
    chosen: Arc<Mutex<Option<(String, Arc<Vec<u8>>)>>>,
    updating: Arc<AtomicBool>,
    /// The last analysis report, for "Save report".
    report: Arc<Mutex<Option<serde_json::Value>>>,
}

#[derive(Serialize)]
struct OpenInfo {
    name: String,
    /// [width, height] in points.
    pages: Vec<[f32; 2]>,
    ready_ms: u64,
}

#[derive(Serialize)]
struct OpenResult {
    /// Opened in this window.
    info: Option<OpenInfo>,
    /// Opened in new windows (one process, hence one VM, each).
    elsewhere: usize,
}

#[derive(Serialize)]
struct LineOut {
    rect: [f32; 4],
    text: String,
}

#[derive(Serialize)]
struct HitOut {
    page: u32,
    rect: [f32; 4],
}

type R<T> = Result<T, String>;

fn err(e: impl std::fmt::Display) -> String {
    let s = format!("{e:#}");
    if s.starts_with(airlock_core::live::VM_STOPPED) || s.starts_with("protocol violation") {
        log_event(&s);
    }
    s
}

/// A small log of things worth knowing afterwards (why a VM stopped):
/// $XDG_STATE_HOME/airlock/app.log, restarted when over 1 MB.
fn log_event(msg: &str) {
    use std::io::Write;
    let dir = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/state")))
        .map(|d| d.join("airlock"));
    let Some(dir) = dir else { return };
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("app.log");
    if std::fs::metadata(&path).is_ok_and(|m| m.len() > 1 << 20) {
        let _ = std::fs::remove_file(&path);
    }
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(f, "{secs} pid {} {}", std::process::id(), text::sanitize_line(msg.as_bytes()));
    }
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> R<T> + Send + 'static) -> R<T> {
    tauri::async_runtime::spawn_blocking(f).await.map_err(err)?
}

/// Plain-language reasons for a document that cannot be displayed.
fn open_error(e: impl std::fmt::Display) -> String {
    let s = format!("{e:#}");
    if s.contains("RenderFailed") {
        "nothing to display: the file has no visible content (an Excel add-in, for example) or is damaged".into()
    } else if s.contains("UnsupportedType") {
        "not a PDF or Office document".into()
    } else if s.contains("TooManyPages") {
        "too many pages (more than 2000)".into()
    } else {
        s
    }
}

fn open_impl(doc: Arc<Mutex<Option<Doc>>>, chosen: Arc<Mutex<Option<(String, Arc<Vec<u8>>)>>>, path: PathBuf) -> R<OpenInfo> {
    let meta = std::fs::metadata(&path).map_err(err)?;
    if !meta.is_file() || meta.len() > MAX_DOC_BYTES {
        return Err("not a file, or larger than 256 MiB".into());
    }
    let bytes = Arc::new(std::fs::read(&path).map_err(err)?);
    // File names are attacker-chosen too ("invoice\u{202E}fdp.exe").
    let name = path.file_name().map(|n| text::sanitize_line(n.as_encoded_bytes())).unwrap_or_default();
    *chosen.lock().unwrap() = Some((name.clone(), bytes.clone()));
    open_bytes(doc, name, &bytes)
}

/// Boots a fresh VM for the document (closing this window's previous one).
fn open_bytes(doc: Arc<Mutex<Option<Doc>>>, name: String, bytes: &[u8]) -> R<OpenInfo> {
    // Close the previous VM before booting a new one.
    if let Some(old) = doc.lock().unwrap().take() {
        old.session.close();
    }
    let session = LiveSession::open(bytes).map_err(open_error)?;
    let info = OpenInfo {
        name,
        pages: session.pages.iter().map(|p| [p.width, p.height]).collect(),
        ready_ms: session.boot_time.as_millis() as u64,
    };
    *doc.lock().unwrap() = Some(Doc { session });
    Ok(info)
}

/// This program, for opening more windows (after an update replaced the
/// binary, /proc/self/exe names the old, deleted one).
fn self_exe() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let s = exe.to_string_lossy();
    Some(s.strip_suffix(" (deleted)").map(PathBuf::from).unwrap_or(exe))
}

/// Opens each document in its own new window: a separate airlock process
/// with its own VM, so documents never share a renderer.
fn open_elsewhere(paths: &[PathBuf]) -> usize {
    let Some(exe) = self_exe() else { return 0 };
    paths
        .iter()
        .filter(|p| {
            let child = std::process::Command::new(&exe)
                .arg(p)
                .stdin(std::process::Stdio::null())
                // Test hooks are for this window only.
                .env_remove("AIRLOCK_DEMO")
                .env_remove("AIRLOCK_TEST_SAVE_DIR")
                .env_remove("AIRLOCK_TEST_SAVE_NAME")
                .spawn();
            match child {
                // Collect its exit status when it closes (no zombie left behind).
                Ok(mut c) => {
                    std::thread::spawn(move || c.wait());
                    true
                }
                Err(_) => false,
            }
        })
        .count()
}

/// The first document opens here unless one already is; the rest get new windows.
fn open_many(doc: Arc<Mutex<Option<Doc>>>, chosen: Arc<Mutex<Option<(String, Arc<Vec<u8>>)>>>, paths: Vec<PathBuf>) -> R<OpenResult> {
    let Some((first, rest)) = paths.split_first() else { return Ok(OpenResult { info: None, elsewhere: 0 }) };
    if doc.lock().unwrap().is_some() {
        return Ok(OpenResult { info: None, elsewhere: open_elsewhere(&paths) });
    }
    let elsewhere = open_elsewhere(rest);
    Ok(OpenResult { info: Some(open_impl(doc, chosen, first.clone())?), elsewhere })
}

#[tauri::command]
async fn pick_and_open(app: tauri::AppHandle, state: State<'_, AppState>) -> R<OpenResult> {
    let (doc, chosen) = (state.doc.clone(), state.chosen.clone());
    blocking(move || {
        let picked = app
            .dialog()
            .file()
            .set_title("Open documents in airlock")
            .add_filter("Documents", &["pdf", "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "pptm", "odt", "ods", "odp", "rtf", "dotm", "dotx", "xlam", "xltm", "xltx", "potm", "ppsm", "ppsx"])
            .add_filter("All files", &["*"])
            .blocking_pick_files()
            .unwrap_or_default();
        let paths = picked.into_iter().filter_map(|p| p.into_path().ok()).collect();
        open_many(doc, chosen, paths)
    })
    .await
}

/// A new VM for the same document (after its VM stopped).
#[tauri::command]
async fn reopen(state: State<'_, AppState>) -> R<OpenInfo> {
    let (doc, chosen) = (state.doc.clone(), state.chosen.clone());
    blocking(move || {
        let (name, bytes) = chosen.lock().unwrap().clone().ok_or("no document chosen")?;
        open_bytes(doc, name, &bytes)
    })
    .await
}

/// Dropped files.
#[tauri::command]
async fn open_paths(paths: Vec<String>, state: State<'_, AppState>) -> R<OpenResult> {
    let (doc, chosen) = (state.doc.clone(), state.chosen.clone());
    blocking(move || open_many(doc, chosen, paths.into_iter().map(PathBuf::from).collect())).await
}

#[tauri::command]
async fn open_path(path: String, state: State<'_, AppState>) -> R<OpenInfo> {
    let (doc, chosen) = (state.doc.clone(), state.chosen.clone());
    blocking(move || open_impl(doc, chosen, PathBuf::from(path))).await
}

/// Name of the file that can be analyzed (also after a failed open).
#[tauri::command]
fn chosen_name(state: State<'_, AppState>) -> Option<String> {
    state.chosen.lock().unwrap().as_ref().map(|(n, _)| n.clone())
}

#[tauri::command]
fn initial_path(state: State<'_, AppState>) -> Option<String> {
    state.initial.lock().unwrap().take().map(|p| p.to_string_lossy().into_owned())
}

/// Test hook: AIRLOCK_DEMO="search=word;analyze" drives the UI after opening.
#[tauri::command]
fn demo_script() -> Option<String> {
    std::env::var("AIRLOCK_DEMO").ok()
}

#[tauri::command]
async fn render_page(page: u32, dpi: u32, state: State<'_, AppState>) -> R<Response> {
    let doc = state.doc.clone();
    blocking(move || {
        let mut g = doc.lock().unwrap();
        let d = g.as_mut().ok_or("no document open")?;
        let img = d.session.render(page, dpi).map_err(err)?;
        let mut out = Vec::with_capacity(img.rgb.len() / 4);
        {
            let mut enc = png::Encoder::new(&mut out, img.width, img.height);
            enc.set_color(png::ColorType::Rgb);
            enc.set_depth(png::BitDepth::Eight);
            enc.set_compression(png::Compression::Fast);
            enc.write_header().map_err(err)?.write_image_data(&img.rgb).map_err(err)?;
        }
        Ok(Response::new(out))
    })
    .await
}

#[tauri::command]
async fn search(query: String, state: State<'_, AppState>) -> R<Vec<HitOut>> {
    let doc = state.doc.clone();
    blocking(move || {
        let mut g = doc.lock().unwrap();
        let d = g.as_mut().ok_or("no document open")?;
        Ok(d.session.search(&query).map_err(err)?.into_iter().map(|h| HitOut { page: h.page, rect: h.rect }).collect())
    })
    .await
}

#[tauri::command]
fn pixels_only(state: State<'_, AppState>) -> bool {
    state.pixels_only.load(Ordering::SeqCst)
}

#[tauri::command]
fn set_pixels_only(on: bool, state: State<'_, AppState>) {
    state.pixels_only.store(on, Ordering::SeqCst);
}

fn text_allowed(state: &AppState) -> R<()> {
    if state.pixels_only.load(Ordering::SeqCst) {
        return Err("pixels-only mode: no text leaves the VM".into());
    }
    Ok(())
}

#[tauri::command]
async fn page_text(page: u32, state: State<'_, AppState>) -> R<String> {
    text_allowed(&state)?;
    let doc = state.doc.clone();
    blocking(move || {
        let mut g = doc.lock().unwrap();
        let d = g.as_mut().ok_or("no document open")?;
        d.session.text(page).map_err(err)
    })
    .await
}

/// Text lines + boxes for the invisible, selectable layer over a page.
#[tauri::command]
async fn page_lines(page: u32, state: State<'_, AppState>) -> R<Vec<LineOut>> {
    text_allowed(&state)?;
    let doc = state.doc.clone();
    blocking(move || {
        let mut g = doc.lock().unwrap();
        let d = g.as_mut().ok_or("no document open")?;
        Ok(d.session.lines(page).map_err(err)?.into_iter().map(|l| LineOut { rect: l.rect, text: l.text }).collect())
    })
    .await
}

/// Findings from the in-VM monitor while *viewing* (normally empty).
#[tauri::command]
fn viewing_findings(state: State<'_, AppState>) -> serde_json::Value {
    match state.doc.lock().unwrap().as_ref() {
        Some(d) if !d.session.indicators.is_empty() => report::Report::build(&d.session.indicators, None, &[]).to_json(),
        _ => serde_json::Value::Null,
    }
}

/// Full behavioural analysis in separate microVMs; viewing continues meanwhile.
#[tauri::command]
async fn analyze(state: State<'_, AppState>) -> R<serde_json::Value> {
    let (name, bytes) = state.chosen.lock().unwrap().clone().ok_or("no document chosen")?;
    let report = state.report.clone();
    blocking(move || {
        let started = std::time::Instant::now();
        let a = analysis::run(&bytes, "analyze", false, &|_| {}).map_err(err)?;
        let mut j = a.report.to_json();
        j["document"] = name.into();
        j["seconds"] = (started.elapsed().as_secs_f32() as f64).into();
        *report.lock().unwrap() = Some(j.clone());
        Ok(j)
    })
    .await
}

/// "invoice.pdf" -> "invoice"
fn stem(name: &str) -> &str {
    name.rsplit_once('.').map_or(name, |(s, _)| s).trim()
}

fn save_dialog(app: &tauri::AppHandle, title: &str, name: &str, filters: &[(&str, &[&str])]) -> Option<PathBuf> {
    // Test hook (like AIRLOCK_DEMO): save into this folder without asking.
    if let Some(dir) = std::env::var_os("AIRLOCK_TEST_SAVE_DIR") {
        return Some(PathBuf::from(dir).join(std::env::var("AIRLOCK_TEST_SAVE_NAME").unwrap_or_else(|_| name.to_string())));
    }
    let mut d = app.dialog().file().set_title(title).set_file_name(name);
    for (label, ext) in filters {
        d = d.add_filter(*label, ext);
    }
    d.blocking_save_file().and_then(|p| p.into_path().ok())
}

/// Write to a temporary name, then rename: never a half-written file.
fn write_atomic(dest: &std::path::Path, f: impl FnOnce(std::fs::File) -> std::io::Result<()>) -> R<()> {
    let part = dest.with_extension("part");
    let r = std::fs::File::create(&part).and_then(f).and_then(|_| std::fs::rename(&part, dest));
    if r.is_err() {
        let _ = std::fs::remove_file(&part);
    }
    r.map_err(err)
}

/// A copy safe to keep, share or open anywhere: a new PDF of the VM's
/// pixels only (no text, links, scripts, fonts or embedded files survive).
#[tauri::command]
async fn save_safe_copy(app: tauri::AppHandle, state: State<'_, AppState>) -> R<Option<String>> {
    const DPI: u32 = 150;
    let (doc, chosen) = (state.doc.clone(), state.chosen.clone());
    blocking(move || {
        let name = chosen.lock().unwrap().as_ref().map(|(n, _)| n.clone()).unwrap_or_default();
        let sizes: Vec<[f32; 2]> = doc.lock().unwrap().as_ref().ok_or("no document open")?.session.pages.iter().map(|p| [p.width, p.height]).collect();
        let Some(dest) = save_dialog(&app, "Save a safe copy (pixels only)", &format!("{}-safe.pdf", stem(&name)), &[("PDF", &["pdf"])]) else {
            return Ok(None);
        };
        write_atomic(&dest, |file| {
            let mut w = airlock_core::pdf::Writer::new(std::io::BufWriter::new(file), sizes.len())?;
            for (i, [wpt, hpt]) in sizes.iter().enumerate() {
                let _ = app.emit("export-progress", (i + 1, sizes.len()));
                // One page at a time, so viewing goes on in between.
                let img = {
                    let mut g = doc.lock().unwrap();
                    let d = g.as_mut().ok_or_else(|| std::io::Error::other("document closed"))?;
                    d.session.render(i as u32, DPI).map_err(|e| std::io::Error::other(format!("{e:#}")))?
                };
                w.add(&img, *wpt, *hpt)?;
            }
            w.finish()?.into_inner().map_err(|e| e.into_error())?.sync_all()
        })?;
        Ok(Some(dest.display().to_string()))
    })
    .await
}

/// The report as plain text (the host's own rendering, plus which file).
fn report_text(j: &serde_json::Value) -> String {
    let body = j["text"].as_str().unwrap_or("");
    let (first, rest) = body.split_once('\n').unwrap_or((body, ""));
    format!("{first}\ndocument: {} (analyzed in {:.1}s)\n{rest}", j["document"].as_str().unwrap_or(""), j["seconds"].as_f64().unwrap_or(0.0))
}

#[tauri::command]
async fn save_report(app: tauri::AppHandle, state: State<'_, AppState>) -> R<Option<String>> {
    let report = state.report.clone();
    blocking(move || {
        let j = report.lock().unwrap().clone().ok_or("no analysis yet")?;
        let name = format!("{}-airlock-report.txt", stem(j["document"].as_str().unwrap_or("document")));
        let Some(dest) = save_dialog(&app, "Save the analysis report", &name, &[("Text", &["txt"]), ("JSON", &["json"])]) else {
            return Ok(None);
        };
        let json = dest.extension().is_some_and(|e| e.eq_ignore_ascii_case("json"));
        let body = if json { serde_json::to_string_pretty(&j).map_err(err)? + "\n" } else { report_text(&j) };
        write_atomic(&dest, |mut f| std::io::Write::write_all(&mut f, body.as_bytes()))?;
        Ok(Some(dest.display().to_string()))
    })
    .await
}

#[tauri::command]
async fn close_document(state: State<'_, AppState>) -> R<()> {
    let doc = state.doc.clone();
    blocking(move || {
        if let Some(d) = doc.lock().unwrap().take() {
            d.session.close();
        }
        Ok(())
    })
    .await
}

/// Puts WebKit's web-content process (where document text is drawn) in
/// WebKitGTK's own bubblewrap + seccomp sandbox, which the 4.1 API leaves
/// off by default. Skipped only if its helpers are missing, so the app
/// still starts; `airlock doctor` reports that case.
fn sandbox_web_content() {
    let has = |cmd: &str| std::env::var_os("PATH").is_some_and(|p| std::env::split_paths(&p).any(|d| d.join(cmd).is_file()));
    if std::env::var_os("WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS").is_some() {
        eprintln!("airlock: WARNING: web-content sandbox disabled by the environment");
    } else if has("bwrap") && has("xdg-dbus-proxy") {
        // Single-threaded here: nothing else reads the environment yet.
        std::env::set_var("WEBKIT_FORCE_SANDBOX", "1");
        // The sandbox mounts the user cache dir read-write (shader caches);
        // give it an airlock-only one instead of all of ~/.cache.
        let base = std::env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")));
        if let Some(dir) = base.map(|b| b.join("airlock")) {
            if std::fs::create_dir_all(&dir).is_ok() {
                std::env::set_var("XDG_CACHE_HOME", dir);
            }
        }
    } else {
        eprintln!("airlock: WARNING: install bubblewrap and xdg-dbus-proxy to sandbox the web view");
    }
}

// ---------------------------------------------------------------- updates
// Updates rebuild the VM with scripts/update.sh (verified downloads from the
// official servers, regression suite, auto-restore). It runs from the update
// kit installed next to this app, or else from the source checkout.

fn source_tree() -> Option<PathBuf> {
    let exe_dir = std::env::current_exe().ok().and_then(|p| p.parent().map(PathBuf::from));
    [
        std::env::var_os("AIRLOCK_SOURCE").map(PathBuf::from),
        exe_dir.map(|d| d.join("../lib/airlock/kit")),
        Some(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")),
    ]
    .into_iter()
    .flatten()
    .find(|p| p.join("scripts/update.sh").is_file())
}

#[derive(Serialize, Default)]
struct UpdateStatus {
    /// A source checkout to update from was found.
    supported: bool,
    available: bool,
    /// Unix time of the check.
    checked: u64,
    /// "MuPDF 1.27.2-r0 → 1.27.3-r0", renderers first.
    changes: Vec<String>,
    packages: u32,
    image_age_days: u32,
    error: Option<String>,
}

fn parse_status(text: &str) -> UpdateStatus {
    let mut st = UpdateStatus { supported: true, ..Default::default() };
    for line in text.lines() {
        let Some((k, v)) = line.split_once('=') else { continue };
        let pair = |label: &str| {
            let (a, b) = v.split_once(' ').unwrap_or((v, v));
            (a != b).then(|| format!("{label} {a} → {b}"))
        };
        match k {
            "checked" => st.checked = v.parse().unwrap_or(0),
            "available" => st.available = v == "1",
            "packages" => st.packages = v.parse().unwrap_or(0),
            "image_age_days" => st.image_age_days = v.parse().unwrap_or(0),
            "kernel" => st.changes.extend(pair("Guest kernel")),
            "firecracker" => st.changes.extend(pair("Firecracker")),
            "alpine" => st.changes.extend(pair("Alpine base")),
            "rules" => st.changes.extend(pair("Malware signatures")),
            "pkg" => {
                let f: Vec<&str> = v.split_whitespace().collect();
                if let [name, old, new] = f[..] {
                    st.changes.push(format!("{name} {old} → {new}"));
                }
            }
            _ => {}
        }
    }
    st
}

/// Checks for updates (network: kernel.org, GitHub, Alpine's mirror). The
/// result is cached for a day unless `force`.
#[tauri::command]
async fn update_status(force: bool) -> R<UpdateStatus> {
    blocking(move || {
        let Some(tree) = source_tree() else { return Ok(UpdateStatus::default()) };
        let cache = tree.join("build/update-status");
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        if !force {
            if let Ok(text) = std::fs::read_to_string(&cache) {
                let st = parse_status(&text);
                if now.saturating_sub(st.checked) < 86_400 {
                    return Ok(st);
                }
            }
        }
        let out = std::process::Command::new(tree.join("scripts/update.sh")).arg("--status").output().map_err(err)?;
        if !out.status.success() {
            let msg = String::from_utf8_lossy(&out.stderr).lines().last().unwrap_or("check failed").to_string();
            return Ok(UpdateStatus { supported: true, error: Some(msg), ..Default::default() });
        }
        Ok(parse_status(&String::from_utf8_lossy(&out.stdout)))
    })
    .await
}

#[derive(Serialize)]
struct UpdateResult {
    ok: bool,
    /// Summary (success) or the end of the log (failure).
    lines: Vec<String>,
    /// This app's own binary was replaced: restart to use the new one.
    restart: bool,
}

/// Runs scripts/update.sh, streaming its progress as "update-progress" events.
#[tauri::command]
async fn run_update(app: tauri::AppHandle, state: State<'_, AppState>) -> R<UpdateResult> {
    let updating = state.updating.clone();
    if updating.swap(true, Ordering::SeqCst) {
        return Err("an update is already running".into());
    }
    let result = blocking(move || {
        use std::io::BufRead;
        let tree = source_tree().ok_or("no airlock source checkout found to update from")?;
        let mut child = std::process::Command::new("sh")
            .arg("-c")
            .arg("exec scripts/update.sh 2>&1")
            .current_dir(&tree)
            .stdout(std::process::Stdio::piped())
            .spawn()
            .map_err(err)?;
        let mut tail: Vec<String> = Vec::new();
        for line in std::io::BufReader::new(child.stdout.take().unwrap()).lines().map_while(Result::ok) {
            let line = text::sanitize_line(line.as_bytes());
            let _ = app.emit("update-progress", line.clone());
            tail.push(line);
            if tail.len() > 40 {
                tail.remove(0);
            }
        }
        let ok = child.wait().map_err(err)?.success();
        let _ = std::fs::remove_file(tree.join("build/update-status"));
        let lines = if ok { tail.iter().skip_while(|l| !l.starts_with("==> Updated")).cloned().collect() } else { tail };
        let restart = std::fs::read_link("/proc/self/exe").is_ok_and(|p| p.to_string_lossy().ends_with(" (deleted)"));
        Ok(UpdateResult { ok, lines, restart })
    })
    .await;
    updating.store(false, Ordering::SeqCst);
    result
}

#[tauri::command]
fn restart_app(app: tauri::AppHandle, state: State<'_, AppState>) {
    if let Some(d) = state.doc.lock().unwrap().take() {
        d.session.close();
    }
    app.restart();
}

fn main() {
    sandbox_web_content();
    let state = AppState::default();
    let mut args: Vec<PathBuf> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    // "airlock-app a.pdf b.docx": the first here, the others in their own windows.
    if args.len() > 1 {
        open_elsewhere(&args.split_off(1));
    }
    *state.initial.lock().unwrap() = args.pop();
    state.pixels_only.store(std::env::var_os("AIRLOCK_PIXELS_ONLY").is_some(), Ordering::SeqCst);
    let doc = state.doc.clone();
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(state)
        .setup(|app| {
            // Its own data directory: otherwise WebKit uses (and its sandbox
            // mounts read-write) the whole ~/.cache.
            let data = app.path().app_local_data_dir()?.join("webview");
            tauri::WebviewWindowBuilder::new(app, "main", tauri::WebviewUrl::default())
                .title("airlock")
                .inner_size(1280.0, 860.0)
                .min_inner_size(720.0, 480.0)
                .data_directory(data)
                .build()?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            pick_and_open,
            open_path,
            open_paths,
            reopen,
            save_safe_copy,
            save_report,
            initial_path,
            demo_script,
            render_page,
            search,
            page_text,
            page_lines,
            pixels_only,
            chosen_name,
            update_status,
            run_update,
            restart_app,
            set_pixels_only,
            viewing_findings,
            analyze,
            close_document
        ])
        .on_window_event(move |_w, e| {
            if let tauri::WindowEvent::Destroyed = e {
                if let Some(d) = doc.lock().unwrap().take() {
                    d.session.close();
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running airlock");
}
