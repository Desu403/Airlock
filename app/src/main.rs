//! airlock desktop app. The webview never sees document bytes: it gets PNGs
//! encoded here from validated pixels, numbers, and sanitised text.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use airlock_core::live::{is_spreadsheet, Layout, LiveSession};
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
    /// An archive or e-mail: its files are listed in the side panel (archive_entries).
    archive: bool,
    /// An e-mail (the panel says "Attachments").
    email: bool,
    /// Offers the spreadsheet layout choice.
    spreadsheet: bool,
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
    if s.starts_with(airlock_core::live::VM_STOPPED) || s.starts_with(airlock_core::live::TRIPWIRE) || s.starts_with("protocol violation") {
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
        "not a document, picture or text file airlock can show".into()
    } else if s.contains("TooManyPages") {
        "too many pages (more than 2000)".into()
    } else {
        s
    }
}

/// This window shows one file of an archive ("--entry N --entry-name NAME
/// archive"): the archive's bytes go to the VM, which unpacks that file.
static ENTRY: std::sync::OnceLock<(u32, String)> = std::sync::OnceLock::new();
/// The opened document's path, so a file inside it can open in a new window.
static OPENED_PATH: Mutex<Option<PathBuf>> = Mutex::new(None);

fn open_impl(doc: Arc<Mutex<Option<Doc>>>, chosen: Arc<Mutex<Option<(String, Arc<Vec<u8>>)>>>, path: PathBuf) -> R<OpenInfo> {
    *OPENED_PATH.lock().unwrap() = Some(path.clone());
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
    let layout = if SHEETS_SINGLE.load(Ordering::SeqCst) { Layout::OnePagePerSheet } else { Layout::Pages };
    // Inside an archive the file's own name gives its type hint and title.
    let entry = ENTRY.get();
    let hint = entry.map(|(_, n)| n.as_str()).unwrap_or(&name);
    let session = LiveSession::open_with(bytes, layout, Some(hint), entry.map(|(i, _)| *i)).map_err(open_error)?;
    let archive = entry.is_none() && airlock_core::live::has_files(bytes);
    let email = archive && (airlock_core::live::is_email(bytes) || airlock_core::live::is_outlook(bytes));
    let name = match entry {
        Some((_, inner)) => format!("{name} › {}", inner.rsplit(['/', '\\']).next().unwrap_or(inner)),
        None => name,
    };
    let info = OpenInfo {
        name,
        archive,
        email,
        spreadsheet: is_spreadsheet(bytes),
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
    paths.iter().filter(|p| open_window(Some(p))).count()
}

/// A new airlock window (its own process, so its own VM), optionally with a document.
fn open_window(path: Option<&PathBuf>) -> bool {
    let Some(exe) = self_exe() else { return false };
    let mut cmd = std::process::Command::new(&exe);
    cmd.args(path)
        .stdin(std::process::Stdio::null())
        // Test hooks are for this window only.
        .env_remove("AIRLOCK_DEMO")
        .env_remove("AIRLOCK_TEST_SAVE_DIR")
        .env_remove("AIRLOCK_TEST_SAVE_NAME");
    match cmd.spawn() {
        // Collect its exit status when it closes (no zombie left behind).
        Ok(mut c) => {
            std::thread::spawn(move || c.wait());
            true
        }
        Err(_) => false,
    }
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

/// Everything airlock opens: the Open dialog's filters and the "Supported
/// files" list in About airlock come from here. The type is always decided
/// by content inside the VM; extensions only help people find their files.
const SUPPORTED: &[(&str, &[&str], &str)] = &[
    ("Documents", &["pdf", "doc", "docx", "docm", "dot", "dotx", "dotm", "rtf", "odt", "xls", "xlsx", "xlsm", "xlsb", "xlam", "xltx", "xltm", "ods", "csv",
        "ppt", "pptx", "pptm", "pps", "ppsx", "ppsm", "potx", "potm", "odp"], "PDF, Word, Excel, PowerPoint, OpenDocument, RTF"),
    ("E-mails", &["eml", "msg"], "e-mail messages and Outlook messages; attachments open in their own VM"),
    ("Archives", &["zip", "7z", "rar", "tar", "gz", "tgz", "bz2", "xz", "cab", "iso"], "each file inside opens in its own VM"),
    ("Pictures", &["png", "jpg", "jpeg", "gif", "webp", "bmp", "tif", "tiff", "svg", "heic", "avif", "ico", "jp2", "psd"], "shown as plain pixels"),
    ("Text and code", &["txt", "md", "log", "json", "xml", "yaml", "yml", "ini", "toml", "html", "htm", "css", "js", "ts", "py", "c", "h", "cpp", "hpp", "cc",
        "java", "rs", "go", "sh", "ps1", "vbs", "bat", "cmd", "hta", "php", "rb", "sql"], "colour-coded; any other plain-text file opens too"),
];

fn all_supported() -> Vec<&'static str> {
    SUPPORTED.iter().flat_map(|(_, exts, _)| exts.iter().copied()).collect()
}

/// For About airlock: (category, extensions, note).
#[tauri::command]
fn supported_files() -> Vec<(String, Vec<String>, String)> {
    SUPPORTED.iter().map(|(l, e, n)| (l.to_string(), e.iter().map(|x| x.to_string()).collect(), n.to_string())).collect()
}

#[tauri::command]
async fn pick_and_open(app: tauri::AppHandle, state: State<'_, AppState>) -> R<OpenResult> {
    let (doc, chosen) = (state.doc.clone(), state.chosen.clone());
    blocking(move || {
        let picked = app
            .dialog()
            .file()
            .set_title("Open documents in airlock")
            .add_filter("All supported files", &all_supported());
        let picked = SUPPORTED.iter().fold(picked, |d, (label, exts, _)| d.add_filter(*label, exts))
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

/// Spreadsheet layout for documents opened from now on (the UI reopens).
static SHEETS_SINGLE: AtomicBool = AtomicBool::new(false);

#[tauri::command]
fn set_sheet_layout(single: bool) {
    SHEETS_SINGLE.store(single, Ordering::SeqCst);
}

/// "Exit airlock" from a window: every window closes properly.
#[tauri::command]
fn quit_everything(app: tauri::AppHandle) {
    quit_all(&app);
}

/// "Close this window": its VM stops and its copy of the document is deleted.
#[tauri::command]
fn close_window(app: tauri::AppHandle) {
    shutdown(&app);
}

#[tauri::command]
fn new_window() -> bool {
    open_window(None)
}

#[derive(Serialize)]
struct EntryInfo {
    index: u32,
    size: u64,
    flags: Vec<String>,
    name: String,
}

/// The open archive's files, as its VM lists them.
#[tauri::command]
async fn archive_entries(state: State<'_, AppState>) -> R<Vec<EntryInfo>> {
    let (doc, chosen) = (state.doc.clone(), state.chosen.clone());
    blocking(move || {
        let is_archive = chosen.lock().unwrap().as_ref().is_some_and(|(_, b)| airlock_core::live::has_files(b)) && ENTRY.get().is_none();
        if !is_archive {
            return Ok(Vec::new());
        }
        let mut g = doc.lock().unwrap();
        let d = g.as_mut().ok_or("no document open")?;
        Ok(d.session.entries().map_err(err)?.into_iter().map(|(index, size, flags, name)| EntryInfo { index, size, flags, name }).collect())
    })
    .await
}

/// A file of the open archive, in a new window with a VM of its own.
#[tauri::command]
fn open_entry(index: u32, name: String) -> R<()> {
    let path = OPENED_PATH.lock().unwrap().clone().ok_or("the archive's file is not known")?;
    let exe = self_exe().ok_or("airlock's program was not found")?;
    let name = text::sanitize_line(name.as_bytes());
    let mut c = std::process::Command::new(exe)
        .args(["--entry".as_ref(), index.to_string().as_ref(), "--entry-name".as_ref(), std::ffi::OsStr::new(&name), path.as_os_str()])
        .stdin(std::process::Stdio::null())
        .env_remove("AIRLOCK_DEMO")
        .spawn()
        .map_err(err)?;
    std::thread::spawn(move || c.wait());
    Ok(())
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

/// Hints that the text came from an AI chat tool (first 30 pages). Counts of
/// characters the sanitiser removes come from the VM as numbers only.
#[tauri::command]
async fn ai_hints(state: State<'_, AppState>) -> R<serde_json::Value> {
    text_allowed(&state)?;
    let doc = state.doc.clone();
    blocking(move || {
        let mut g = doc.lock().unwrap();
        let d = g.as_mut().ok_or("no document open")?;
        let mut stats = std::collections::BTreeMap::<String, u64>::new();
        let mut text = String::new();
        for p in 0..d.session.pages.len().min(30) as u32 {
            for (k, v) in d.session.text_stats(p).map_err(err)? {
                *stats.entry(k).or_default() += v;
            }
            text.push_str(&d.session.text(p).map_err(err)?);
            text.push('\n');
        }
        Ok(airlock_core::aitext::analyze(&stats, &text).to_json())
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
    let (report, chosen) = (state.report.clone(), state.chosen.clone());
    blocking(move || {
        let started = std::time::Instant::now();
        let entry = ENTRY.get();
        let hint = entry.map(|(_, n)| n.clone()).unwrap_or_else(|| name.clone());
        let a = analysis::run(&bytes, Some(&hint), entry.map(|(i, _)| *i), "analyze", false, &|_| {}).map_err(err)?;
        let mut j = a.report.to_json();
        j["document"] = name.into();
        j["seconds"] = (started.elapsed().as_secs_f32() as f64).into();
        j["log"] = a.log.iter().map(|(t, l)| serde_json::json!([t, l])).collect::<Vec<_>>().into();
        // Kept for "Save report" only if that file is still the one open
        // (an automatic check can finish after another file was opened).
        if chosen.lock().unwrap().as_ref().is_some_and(|(_, b)| Arc::ptr_eq(b, &bytes)) {
            *report.lock().unwrap() = Some(j.clone());
        }
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
    let chosen = d.blocking_save_file()?;
    match chosen.clone().into_path() {
        Ok(p) => Some(p),
        Err(e) => {
            log_event(&format!("save dialog returned a location that is not a file path ({chosen}): {e}"));
            None
        }
    }
}

/// Write to a temporary name, then rename: never a half-written file.
/// Where the folder does not allow a temporary file next to the target
/// (some file-chooser portals grant the chosen name only), it is written in
/// place. Failures are logged with the path.
fn write_atomic(dest: &std::path::Path, f: impl Fn(std::fs::File) -> std::io::Result<()>) -> R<()> {
    let part = dest.with_extension("part");
    let r = match std::fs::File::create(&part) {
        Ok(file) => f(file).and_then(|_| std::fs::rename(&part, dest)).inspect_err(|_| {
            let _ = std::fs::remove_file(&part);
        }),
        Err(_) => std::fs::File::create(dest).and_then(&f),
    };
    r.map_err(|e| {
        log_event(&format!("could not save {}: {e}", dest.display()));
        format!("could not save to {}: {e}", dest.display())
    })
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
/// Every type airlock opens (the same list as scripts/install.sh).
const MIME_TYPES: &[&str] = &[
    "application/pdf",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.ms-word.document.macroEnabled.12",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.ms-excel.sheet.macroEnabled.12",
    "application/vnd.ms-powerpoint",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "application/vnd.ms-powerpoint.presentation.macroEnabled.12",
    "application/vnd.oasis.opendocument.text",
    "application/vnd.oasis.opendocument.spreadsheet",
    "application/vnd.oasis.opendocument.presentation",
    "application/rtf",
    "text/rtf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.template",
    "application/vnd.ms-word.template.macroEnabled.12",
    "application/vnd.ms-excel.addin.macroEnabled.12",
    "application/vnd.ms-excel.template.macroEnabled.12",
    "application/vnd.ms-powerpoint.slideshow.macroEnabled.12",
    // E-mail messages (attachments open like an archive's files).
    "message/rfc822",
    "application/vnd.ms-outlook",
    // Archives (listed inside the VM; each file opens in a VM of its own).
    "application/zip",
    "application/x-7z-compressed",
    "application/vnd.rar",
    "application/x-rar",
    "application/x-rar-compressed",
    "application/x-tar",
    "application/gzip",
    "application/x-bzip2",
    "application/x-xz",
    "application/x-iso9660-image",
    "application/vnd.ms-cab-compressed",
    // Pictures and text / source code (shown syntax-coloured).
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "image/bmp",
    "image/tiff",
    "image/svg+xml",
    "image/avif",
    "image/heic",
    "image/vnd.microsoft.icon",
    "text/plain",
    "text/markdown",
    "text/csv",
    "text/html",
    "text/css",
    "text/xml",
    "application/xml",
    "application/json",
    "application/x-yaml",
    "text/x-csrc",
    "text/x-chdr",
    "text/x-c++src",
    "text/x-c++hdr",
    "text/x-python",
    "text/x-script.python",
    "text/x-java",
    "text/x-rust",
    "text/x-go",
    "application/javascript",
    "text/javascript",
    "application/x-shellscript",
    "text/x-shellscript",
    "application/x-powershell",
    "text/x-log",
];

/// An AppImage is a single file the desktop knows nothing about: register it
/// like an installed app (menu and search entry, "Open with airlock", the
/// window's icon; the window's app id "airlock-app" is matched through
/// StartupWMClass). Rewritten when the AppImage moves. A launcher from
/// scripts/install.sh (without our marker) is left alone. Never changes which
/// app opens a type by default: on first registration the current defaults
/// are pinned first, like scripts/install.sh does.
fn integrate_appimage() {
    let Some(appimage) = std::env::var_os("APPIMAGE").map(PathBuf::from) else { return };
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else { return };
    let data = std::env::var_os("XDG_DATA_HOME").map(PathBuf::from).unwrap_or_else(|| home.join(".local/share"));
    let apps = data.join("applications");
    let desktop = apps.join("airlock.desktop");
    let old = std::fs::read_to_string(&desktop).ok();
    if old.as_deref().is_some_and(|d| !d.contains("X-Airlock-AppImage=true")) {
        return;
    }
    let exe = format!("\"{}\"", appimage.display().to_string().replace('\\', "\\\\").replace('"', "\\\""));
    let entry = format!(
        "[Desktop Entry]\nType=Application\nName=airlock\nGenericName=Safe Document Viewer\n\
         Comment=Open untrusted PDFs and Office files inside a disposable microVM\n\
         Exec={exe} %f\nIcon=airlock\nTerminal=false\nCategories=Office;Viewer;Security;\n\
         Keywords=pdf;docx;xlsx;pptx;malware;sandbox;safe;viewer;\nMimeType={};\n\
         StartupWMClass=airlock-app\nActions=new-window;quit-all;\nX-Airlock-AppImage=true\n\n\
         [Desktop Action new-window]\nName=New window\nExec={exe} --new-window\n\n\
         [Desktop Action quit-all]\nName=Exit airlock (all windows)\nExec={exe} --quit-all\n",
        MIME_TYPES.join(";")
    );
    let icons: [(&str, &[u8]); 6] = [
        ("32x32", include_bytes!("../icons/32x32.png")),
        ("48x48", include_bytes!("../icons/48x48.png")),
        ("64x64", include_bytes!("../icons/64x64.png")),
        ("128x128", include_bytes!("../icons/128x128.png")),
        ("256x256", include_bytes!("../icons/256x256.png")),
        ("512x512", include_bytes!("../icons/icon.png")),
    ];
    let mut changed = false;
    for (size, png) in icons {
        let path = data.join(format!("icons/hicolor/{size}/apps/airlock.png"));
        if std::fs::read(&path).ok().as_deref() != Some(png) {
            changed |= path.parent().is_some_and(|d| std::fs::create_dir_all(d).is_ok()) && std::fs::write(&path, png).is_ok();
        }
    }
    if old.as_deref() != Some(entry.as_str()) {
        if old.is_none() {
            pin_current_defaults(&home);
        }
        if std::fs::create_dir_all(&apps).is_err() || std::fs::write(&desktop, &entry).is_err() {
            return;
        }
        changed = true;
    }
    if changed {
        // Each desktop caches its menu and type associations differently.
        let quiet = |cmd: &str, args: &[&std::ffi::OsStr]| {
            let _ = std::process::Command::new(cmd).args(args).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status();
        };
        quiet("update-desktop-database", &["-q".as_ref(), apps.as_os_str()]);
        quiet("gtk-update-icon-cache", &["-q".as_ref(), "-t".as_ref(), data.join("icons/hicolor").as_os_str()]);
        quiet("kbuildsycoca6", &[]);
        quiet("kbuildsycoca5", &[]);
        log_event(&format!("registered the AppImage with the desktop: {}", appimage.display()));
    }
}

/// Make today's effective default for each type explicit, so adding airlock
/// to "Open with" can never make it the default by accident.
fn pin_current_defaults(home: &std::path::Path) {
    let config = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from).unwrap_or_else(|| home.join(".config"));
    let list = std::fs::read_to_string(config.join("mimeapps.list")).unwrap_or_default();
    let explicit: std::collections::HashSet<&str> = list
        .lines()
        .skip_while(|l| l.trim() != "[Default Applications]")
        .skip(1)
        .take_while(|l| !l.starts_with('['))
        .filter_map(|l| l.split_once('=').map(|(k, _)| k.trim()))
        .collect();
    for t in MIME_TYPES.iter().filter(|t| !explicit.contains(*t)) {
        let Ok(out) = std::process::Command::new("xdg-mime").args(["query", "default", t]).stderr(std::process::Stdio::null()).output() else { return };
        let current = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if !current.is_empty() && current != "airlock.desktop" {
            let _ = std::process::Command::new("xdg-mime").args(["default", &current, t]).stderr(std::process::Stdio::null()).status();
        }
    }
}

/// WebKitGTK's own bubblewrap + seccomp sandbox, which the 4.1 API leaves
/// off by default. Skipped only if its helpers are missing, so the app
/// still starts; `airlock doctor` reports that case.
fn sandbox_web_content() {
    let has = |cmd: &str| std::env::var_os("PATH").is_some_and(|p| std::env::split_paths(&p).any(|d| d.join(cmd).is_file()));
    if std::env::var_os("WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS").is_some() {
        eprintln!("airlock: WARNING: web-content sandbox disabled by the environment");
    } else if std::env::var_os("APPIMAGE").is_some() {
        // The AppImage's bundled WebKit finds its helpers by relative paths,
        // which do not resolve inside its own bubblewrap sandbox: it runs
        // without that extra layer (WebKitGTK's default). Documents still
        // arrive as pixels from the VM; scripts/install.sh keeps the sandbox.
        eprintln!("airlock: note: AppImage build, WebKit's extra web-content sandbox is off");
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

/// The AppImage updates from the kit its setup copied to the user's VM
/// folder (the mounted image is read-only). A newer AppImage refreshes that
/// kit first (.kit-version differs); the pins it carries are its own.
fn appimage_kit() -> Option<PathBuf> {
    std::env::var_os("APPIMAGE")?;
    let bundled = std::env::current_exe().ok()?.parent()?.join("../lib/airlock/kit");
    let user = airlock_lib()?.join("kit");
    if !user.join(".airlock-kit").exists() {
        return None; // not set up yet
    }
    let version = |k: &std::path::Path| std::fs::read_to_string(k.join(".kit-version")).unwrap_or_default();
    if bundled.is_dir() && version(&bundled) != version(&user) {
        for d in ["guest", "guest-agent", "proto", "scripts", "tests"] {
            let _ = std::fs::remove_dir_all(user.join(d));
            let ok = std::process::Command::new("cp").arg("-r").arg(bundled.join(d)).arg(user.join(d)).status().is_ok_and(|s| s.success());
            if !ok {
                log_event(&format!("could not refresh the update kit ({d})"));
                return None;
            }
        }
        let _ = std::fs::copy(bundled.join(".kit-version"), user.join(".kit-version"));
        let _ = std::fs::copy(bundled.join(".vm-version"), user.join(".vm-version"));
        // Check again now: the new kit may bring viewer features.
        let _ = std::fs::remove_file(user.join("build/update-status"));
        log_event(&format!("update kit refreshed from this AppImage ({})", version(&bundled).trim()));
    }
    Some(user)
}

/// The AppImage's own CLI, for update.sh's checks.
fn appimage_cli() -> Option<PathBuf> {
    std::env::var_os("APPIMAGE")?;
    Some(std::env::current_exe().ok()?.parent()?.join("../lib/airlock/bin/airlock")).filter(|p| p.is_file())
}

fn source_tree() -> Option<PathBuf> {
    if std::env::var_os("APPIMAGE").is_some() {
        return appimage_kit();
    }
    let exe_dir = std::env::current_exe().ok().and_then(|p| p.parent().map(PathBuf::from));
    [
        std::env::var_os("AIRLOCK_SOURCE").map(PathBuf::from),
        exe_dir.map(|d| d.join("../lib/airlock/kit")),
        // Created by the AppImage's first-run setup.
        std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/lib/airlock/kit")),
        Some(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")),
    ]
    .into_iter()
    .flatten()
    .find(|p| p.join("scripts/update.sh").is_file())
}

// ---------------------------------------------------------------- first-run setup
// scripts/setup.sh checks this computer, fixes what needs root with one
// password prompt (pkexec), and builds the VM in user space. The AppImage
// carries it in its resources ("kit"); a source checkout or an install has it too.

/// Where to run setup.sh from, and the bundled sinkhole (AppImage).
fn setup_kit(app: &tauri::AppHandle) -> Option<(PathBuf, Option<PathBuf>)> {
    let res = app.path().resource_dir().ok();
    let sinkhole = res.as_ref().map(|r| r.join("bin/sinkhole")).filter(|p| p.is_file());
    let exe_dir = std::env::current_exe().ok().and_then(|p| p.parent().map(PathBuf::from));
    [
        std::env::var_os("AIRLOCK_SOURCE").map(PathBuf::from),
        res.map(|r| r.join("kit")),
        std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/lib/airlock/kit")),
        exe_dir.map(|d| d.join("../lib/airlock/kit")),
        Some(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")),
    ]
    .into_iter()
    .flatten()
    .find(|p| p.join("scripts/setup.sh").is_file())
    .map(|k| (k, sinkhole))
}

#[derive(Serialize)]
struct SetupItem {
    /// ok, fix (setup can fix it), build (the VM is not built yet), fail
    status: String,
    id: String,
    text: String,
}

fn setup_items(out: &[u8]) -> Vec<SetupItem> {
    String::from_utf8_lossy(out)
        .lines()
        .filter_map(|l| l.strip_prefix("@@"))
        .filter_map(|l| {
            let mut f = l.splitn(3, '\t');
            Some(SetupItem { status: f.next()?.into(), id: f.next()?.into(), text: text::sanitize_line(f.next()?.as_bytes()) })
        })
        .take(40)
        .collect()
}

/// What this computer still needs (empty kit = nothing to check: dev build).
#[tauri::command]
async fn setup_check(app: tauri::AppHandle) -> R<Vec<SetupItem>> {
    blocking(move || {
        let Some((kit, _)) = setup_kit(&app) else { return Ok(Vec::new()) };
        let out = std::process::Command::new("sh").arg("scripts/setup.sh").arg("check").current_dir(&kit).output().map_err(err)?;
        Ok(setup_items(&out.stdout))
    })
    .await
}

/// Applies the root fixes (one password prompt via pkexec).
#[tauri::command]
async fn setup_fix(app: tauri::AppHandle) -> R<Vec<String>> {
    blocking(move || {
        let (kit, _) = setup_kit(&app).ok_or("setup files not found")?;
        let out = std::process::Command::new("sh").arg("scripts/setup.sh").arg("fix").current_dir(&kit).output().map_err(err)?;
        let lines: Vec<String> = String::from_utf8_lossy(&[out.stdout, out.stderr].concat()).lines().map(|l| text::sanitize_line(l.as_bytes())).take(60).collect();
        if out.status.success() { Ok(lines) } else { Err(format!("the fix did not complete: {}", lines.last().cloned().unwrap_or_default())) }
    })
    .await
}

// ---------------------------------------------------------------- settings
// The window's preferences (colours, panel width, toggles) also go to a file:
// every window is its own process, and a new one must not start before an
// older one has flushed its web storage.

fn settings_path(app: &tauri::AppHandle) -> Option<PathBuf> {
    app.path().app_config_dir().ok().map(|d| d.join("settings.json"))
}

#[tauri::command]
fn ui_settings(app: tauri::AppHandle) -> serde_json::Value {
    settings_path(&app)
        .and_then(|p| std::fs::read(p).ok())
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .filter(|v| v.is_object())
        .unwrap_or_else(|| serde_json::json!({}))
}

#[tauri::command]
fn ui_setting_set(app: tauri::AppHandle, key: String, value: String) -> R<()> {
    if !key.starts_with("airlock.") || key.len() > 64 || value.len() > 256 {
        return Err("not a setting".into());
    }
    let path = settings_path(&app).ok_or("no settings folder")?;
    std::fs::create_dir_all(path.parent().unwrap()).map_err(err)?;
    // Read-modify-write under a lock: several windows may save at once.
    let lock = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(path.with_extension("lock")).map_err(err)?;
    let _ = lock.lock();
    let mut all = ui_settings(app.clone());
    all[key] = value.into();
    let tmp = path.with_extension("json.part");
    std::fs::write(&tmp, serde_json::to_vec_pretty(&all).map_err(err)?).map_err(err)?;
    std::fs::rename(&tmp, &path).map_err(err)
}

/// For "About & logs": versions of everything that touches a document, and
/// the app's own log (VM stops, tripwires, updates, errors).
#[tauri::command]
async fn about_info() -> R<serde_json::Value> {
    blocking(|| {
        let mut j = serde_json::json!({ "app": env!("CARGO_PKG_VERSION") });
        j["install"] = match std::env::var_os("APPIMAGE") {
            Some(a) => format!("AppImage: {}", PathBuf::from(a).display()),
            None => format!("installed: {}", std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_default()),
        }
        .into();
        if let Ok(a) = airlock_core::vm::Assets::locate() {
            j["vm_dir"] = a.rootfs.parent().map(|p| p.display().to_string()).unwrap_or_default().into();
            let info = std::fs::read_to_string(a.rootfs.with_file_name("rootfs.info")).unwrap_or_default();
            let mut pkgs = Vec::new();
            for l in info.lines() {
                if let Some(t) = l.strip_prefix("built ") {
                    j["image_built"] = t.trim().parse::<u64>().unwrap_or(0).into();
                } else if let Some(r) = l.strip_prefix("rules ") {
                    j["rules"] = r.into();
                    // ClamAV: the daily database's header ("ClamAV-VDB:<date>:<version>:...")
                    // and how the last refresh went (scripts/clamav-db.sh).
                    let dir = a.rootfs.parent().map(PathBuf::from).unwrap_or_default();
                    if dir.join("clamav.ext4").is_file() {
                        let mut head = [0u8; 160];
                        let n = std::fs::File::open(dir.join("clamav/daily.cvd")).and_then(|mut f| std::io::Read::read(&mut f, &mut head)).unwrap_or(0);
                        let h = String::from_utf8_lossy(&head[..n]).into_owned();
                        let f: Vec<&str> = h.split(':').collect();
                        let status = std::fs::read_to_string(dir.join("clamav.status")).unwrap_or_default();
                        let mut st = status.split_whitespace();
                        j["clamav"] = serde_json::json!({
                            "version": f.get(2).and_then(|v| v.trim().parse::<u64>().ok()),
                            "date": f.get(1).map(|d| text::sanitize_line(d.as_bytes())),
                            "checked": st.next().and_then(|t| t.parse::<u64>().ok()),
                            "state": st.next().map(|s| text::sanitize_line(s.as_bytes())),
                        });
                    }
                    if let Ok(list) = std::fs::read_to_string(a.rootfs.with_file_name("urlhaus.txt")) {
                        j["urlhaus"] = list.lines().count().into();
                    }
                    if let Some((n, updated)) = airlock_core::known::status() {
                        j["known"] = serde_json::json!({ "count": n, "updated": updated });
                    }
                } else if ["mupdf-", "libreoffice-common-", "yara-", "python3-3", "quickjs-", "py3-oletools-", "py3-pygments-2", "zbar-", "7zip-", "imagemagick-7", "clamav-scanner-"].iter().any(|p| l.starts_with(p)) {
                    pkgs.push(l.to_string());
                }
            }
            j["packages"] = pkgs.into();
            // "Linux version 6.1.190 ..." is stored in the kernel image.
            if let Ok(k) = std::fs::read(&a.kernel) {
                let needle = b"Linux version ";
                if let Some(i) = k.windows(needle.len()).position(|w| w == needle) {
                    let end = k[i..].iter().position(|&b| b == 0 || b == b'\n').unwrap_or(0).min(160);
                    j["kernel"] = text::sanitize_line(&k[i..i + end]).into();
                }
            }
            if let Ok(o) = std::process::Command::new(&a.vmm).arg("--version").output() {
                j["firecracker"] = text::sanitize_line(String::from_utf8_lossy(&o.stdout).lines().next().unwrap_or("").as_bytes()).into();
            }
        }
        let log = std::env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/state")))
            .map(|d| d.join("airlock/app.log"));
        let text = log.and_then(|p| std::fs::read(p).ok()).unwrap_or_default();
        let lines: Vec<String> = String::from_utf8_lossy(&text).lines().rev().take(150).map(|l| text::sanitize_line(l.as_bytes())).collect();
        j["log"] = lines.into_iter().rev().collect::<Vec<_>>().into();
        Ok(j)
    })
    .await
}

/// What "Uninstall airlock" would remove: offered for the AppImage only
/// (scripts/install.sh --uninstall removes a source install).
#[derive(Serialize)]
struct UninstallInfo {
    available: bool,
    /// The VM, its build kit and caches.
    lib: String,
    lib_bytes: u64,
    appimage: Option<String>,
    /// System settings from setup's "Fix" that can be undone.
    system: bool,
}

fn airlock_lib() -> Option<PathBuf> {
    std::env::var_os("AIRLOCK_LIB").map(PathBuf::from).or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/lib/airlock")))
}

fn desktop_entry() -> Option<PathBuf> {
    let data = std::env::var_os("XDG_DATA_HOME").map(PathBuf::from).or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))?;
    Some(data.join("applications/airlock.desktop"))
}

fn dir_bytes(dir: &std::path::Path) -> u64 {
    let Ok(rd) = std::fs::read_dir(dir) else { return 0 };
    rd.flatten()
        .map(|e| match e.file_type() {
            Ok(t) if t.is_dir() => dir_bytes(&e.path()),
            Ok(t) if t.is_file() => e.metadata().map(|m| {
                // Space actually used (sparse disk images are mostly holes).
                #[cfg(unix)]
                return std::os::unix::fs::MetadataExt::blocks(&m) * 512;
                #[cfg(not(unix))]
                m.len()
            }).unwrap_or(0),
            _ => 0,
        })
        .sum()
}

#[tauri::command]
async fn uninstall_info() -> R<UninstallInfo> {
    blocking(|| {
        let appimage = std::env::var_os("APPIMAGE").map(PathBuf::from);
        // A launcher from scripts/install.sh means a source install shares
        // this VM: that one is removed with its own --uninstall.
        let source_install = desktop_entry().and_then(|d| std::fs::read_to_string(d).ok()).is_some_and(|d| !d.contains("X-Airlock-AppImage=true"));
        let lib = airlock_lib().ok_or("no home folder")?;
        let system = ["/etc/udev/rules.d/65-airlock.rules", "/etc/sysctl.d/60-airlock-userns.conf", "/etc/modules-load.d/airlock.conf"].iter().any(|f| std::path::Path::new(f).exists());
        Ok(UninstallInfo {
            available: appimage.is_some() && !source_install,
            lib_bytes: dir_bytes(&lib),
            lib: lib.display().to_string(),
            appimage: appimage.map(|p| p.display().to_string()),
            system,
        })
    })
    .await
}

/// Removes everything the AppImage added for this user, optionally the
/// system settings (one password prompt) and the AppImage file, then closes
/// every airlock window. Documents and files the user saved are not touched.
#[tauri::command]
async fn uninstall(app: tauri::AppHandle, system: bool, remove_appimage: bool) -> R<Vec<String>> {
    let info = uninstall_info().await?;
    if !info.available {
        return Err("uninstall is offered for the AppImage only; a source install uses scripts/install.sh --uninstall".into());
    }
    let done = blocking(move || {
        let mut done = Vec::new();
        // System settings first: their undo script lives in the kit.
        if system && info.system {
            let (kit, _) = setup_kit(&app).ok_or("setup files not found")?;
            let out = std::process::Command::new("sh").arg("scripts/setup.sh").arg("unfix").current_dir(&kit).output().map_err(err)?;
            if !out.status.success() {
                return Err("the system settings were not changed (password prompt cancelled?); nothing was removed".to_string());
            }
            done.push("System settings from setup undone".to_string());
        }
        let home = std::env::var_os("HOME").map(PathBuf::from).ok_or("no home folder")?;
        if let Some(d) = desktop_entry() {
            let _ = std::fs::remove_file(&d);
            let data = d.parent().and_then(|p| p.parent()).map(PathBuf::from).unwrap_or_default();
            for size in ["32x32", "48x48", "64x64", "128x128", "256x256", "512x512"] {
                let _ = std::fs::remove_file(data.join(format!("icons/hicolor/{size}/apps/airlock.png")));
            }
            let _ = std::process::Command::new("update-desktop-database").arg("-q").arg(data.join("applications")).status();
            for k in ["kbuildsycoca6", "kbuildsycoca5"] {
                let _ = std::process::Command::new(k).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status();
            }
            done.push("Menu entry, icon and \"Open with\" removed".to_string());
        }
        let lib = PathBuf::from(&info.lib);
        if lib.starts_with(&home) && (lib.join("rootfs.ext4").exists() || lib.join("kit/.airlock-kit").exists()) {
            std::fs::remove_dir_all(&lib).map_err(err)?;
            done.push(format!("Secure viewer removed ({})", info.lib));
        }
        let mut dirs = vec![home.join(".cache/airlock")];
        dirs.extend([app.path().app_local_data_dir(), app.path().app_cache_dir(), app.path().app_config_dir(), app.path().app_data_dir()].into_iter().flatten());
        for d in dirs.iter().filter(|d| d.starts_with(&home) && d.exists()) {
            let _ = std::fs::remove_dir_all(d);
        }
        done.push("Settings and caches removed".to_string());
        if remove_appimage {
            if let Some(a) = &info.appimage {
                // Safe while running: the mounted image stays until exit.
                std::fs::remove_file(a).map_err(err)?;
                done.push(format!("AppImage deleted ({a})"));
            }
        }
        Ok(done)
    })
    .await?;
    log_event(&format!("uninstalled: {}", done.join("; ")));
    Ok(done)
}

/// Reads a build's output as lines; curl redraws its meter with \r, so each
/// redraw is a line too. Lines are sanitised; blank ones are skipped.
fn stream_lines(out: impl std::io::Read, mut f: impl FnMut(String)) {
    use std::io::BufRead;
    let mut out = std::io::BufReader::new(out);
    let mut buf = Vec::new();
    loop {
        buf.clear();
        let Ok(n) = out.read_until(b'\n', &mut buf) else { break };
        if n == 0 {
            break;
        }
        for part in buf.split(|&b| b == b'\r' || b == b'\n') {
            let line = text::sanitize_line(part);
            if !line.trim().is_empty() {
                f(line);
            }
        }
    }
}

/// Builds and installs the VM (user space), streaming "setup-progress".
#[tauri::command]
async fn setup_build(app: tauri::AppHandle, state: State<'_, AppState>) -> R<()> {
    let updating = state.updating.clone();
    if updating.swap(true, Ordering::SeqCst) {
        return Err("a build or update is already running".into());
    }
    let result = blocking(move || {
        let (kit, sinkhole) = setup_kit(&app).ok_or("setup files not found")?;
        let mut cmd = std::process::Command::new("sh");
        // AIRLOCK_PROGRESS: package names, download meters and "@@" step
        // markers for the progress view.
        cmd.arg("-c").arg("exec sh scripts/setup.sh build 2>&1").current_dir(&kit).env("AIRLOCK_PROGRESS", "1").stdout(std::process::Stdio::piped());
        if let Some(s) = sinkhole {
            cmd.env("AIRLOCK_SINKHOLE", s);
        }
        let mut child = cmd.spawn().map_err(err)?;
        let mut last = String::new();
        stream_lines(child.stdout.take().unwrap(), |line| {
            last = line.clone();
            let _ = app.emit("setup-progress", line);
        });
        if child.wait().map_err(err)?.success() { Ok(()) } else { Err(format!("the build stopped: {last}")) }
    })
    .await;
    updating.store(false, Ordering::SeqCst);
    result
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
            "viewer" => st.changes.insert(0, "New viewer features from this version of airlock (pictures, code, scripts…)".into()),
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
        let mut cmd = std::process::Command::new(tree.join("scripts/update.sh"));
        if let Some(cli) = appimage_cli() {
            cmd.env("AIRLOCK_CLI", cli);
        }
        let out = cmd.arg("--status").output().map_err(err)?;
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
        let tree = source_tree().ok_or("no airlock source checkout found to update from")?;
        // One update at a time across every airlock window (each is its own
        // process): an exclusive lock on the kit, held until this one ends.
        let _ = std::fs::create_dir_all(tree.join("build"));
        let lock = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(tree.join("build/.update.lock")).map_err(err)?;
        if lock.try_lock().is_err() {
            return Err("another airlock window is already updating; its progress shows there".to_string());
        }
        let mut cmd = std::process::Command::new("sh");
        // AIRLOCK_PROGRESS: the build's own output (downloads, packages,
        // kernel files, test results) for the live progress view.
        cmd.arg("-c").arg("exec scripts/update.sh 2>&1").current_dir(&tree).env("AIRLOCK_PROGRESS", "1").stdout(std::process::Stdio::piped());
        if let Some(cli) = appimage_cli() {
            cmd.env("AIRLOCK_CLI", cli);
        }
        let mut child = cmd.spawn().map_err(err)?;
        let mut tail: Vec<String> = Vec::new();
        stream_lines(child.stdout.take().unwrap(), |line| {
            let _ = app.emit("update-progress", line.clone());
            // Meter redraws and per-file lines would crowd out the summary.
            if !line.starts_with("@@") && !line.trim_start().starts_with(|c: char| c.is_ascii_digit()) {
                tail.push(line);
                if tail.len() > 40 {
                    tail.remove(0);
                }
            }
        });
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

/// WebKitGTK paces frames from the display's vblank (DRM). When the screen
/// is switched off (DPMS, after a lock) that stops, and on some setups it
/// never restarts: the window keeps its last picture. A timer keeps the
/// GPU renderer (smooth scrolling) and survives the display going away.
fn stable_rendering() {
    if std::env::var_os("WEBKIT_FORCE_VBLANK_TIMER").is_none() {
        std::env::set_var("WEBKIT_FORCE_VBLANK_TIMER", "1");
    }
}

fn main() {
    stable_rendering();
    sandbox_web_content();
    std::thread::spawn(integrate_appimage);
    let state = AppState::default();
    let mut args: Vec<PathBuf> = std::env::args_os().skip(1).map(PathBuf::from).collect();
    // From the launcher's right-click menu (desktop file actions).
    if args.first().is_some_and(|a| a == "--quit-all") {
        for pid in instances().into_iter().filter(|&p| p != std::process::id()) {
            terminate(pid);
        }
        return;
    }
    args.retain(|a| a != "--new-window");
    // "--entry N --entry-name NAME archive": one file of an archive.
    if let Some(i) = args.iter().position(|a| a == "--entry") {
        let n = args.get(i + 1).and_then(|v| v.to_str()).and_then(|v| v.parse::<u32>().ok());
        let name_at = args.iter().position(|a| a == "--entry-name");
        let name = name_at.and_then(|j| args.get(j + 1)).map(|v| text::sanitize_line(v.as_os_str().as_encoded_bytes()));
        if let (Some(n), Some(name)) = (n, name) {
            let _ = ENTRY.set((n, name));
        }
        let mut drop_idx: Vec<usize> = vec![i, i + 1];
        if let Some(j) = name_at {
            drop_idx.extend([j, j + 1]);
        }
        drop_idx.sort_unstable();
        for k in drop_idx.into_iter().rev() {
            if k < args.len() {
                args.remove(k);
            }
        }
    }
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
            handle_sigterm(app.handle());
            start_tray(app.handle());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            uninstall_info,
            uninstall,
            supported_files,
            archive_entries,
            open_entry,
            ui_settings,
            ui_setting_set,
            about_info,
            pick_and_open,
            open_path,
            open_paths,
            reopen,
            quit_everything,
            close_window,
            ai_hints,
            setup_check,
            setup_fix,
            setup_build,
            set_sheet_layout,
            new_window,
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

// ---------------------------------------------------------------- tray icon
// Every document is its own window and process (its own VM). One of them
// shows the tray icon (whoever holds the lock); if it closes, another
// takes over. "Close all documents and quit" asks every airlock window to
// shut down properly: VM stopped, its copy of the document deleted.

/// The airlock windows of this user that are running (by executable).
fn instances() -> Vec<u32> {
    let Some(me) = self_exe() else { return Vec::new() };
    let Ok(rd) = std::fs::read_dir("/proc") else { return Vec::new() };
    rd.flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
        .filter(|pid| {
            std::fs::read_link(format!("/proc/{pid}/exe")).is_ok_and(|p| {
                let s = p.to_string_lossy();
                PathBuf::from(s.strip_suffix(" (deleted)").unwrap_or(&s)) == me
            }) && !std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|st| st.rsplit(')').next().is_some_and(|r| r.trim_start().starts_with('Z')))
        })
        .collect()
}

/// Holds the tray lock while this process lives (flock on an open file).
fn take_tray_lock() -> bool {
    static LOCK: Mutex<Option<std::fs::File>> = Mutex::new(None);
    let dir = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
    let Ok(f) = std::fs::OpenOptions::new().create(true).truncate(false).write(true).open(dir.join("airlock-tray.lock")) else { return false };
    if f.try_lock().is_err() {
        return false;
    }
    *LOCK.lock().unwrap() = Some(f);
    true
}

fn open_count_label() -> String {
    match instances().len() {
        1 => "airlock · 1 window open".into(),
        n => format!("airlock · {n} windows open"),
    }
}

fn build_tray(app: &tauri::AppHandle) -> tauri::Result<()> {
    use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
    use tauri::tray::TrayIconBuilder;
    let count = MenuItem::with_id(app, "count", open_count_label(), false, None::<&str>)?;
    let open = MenuItem::with_id(app, "open", "New window…", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Exit airlock (closes all documents)", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&count, &PredefinedMenuItem::separator(app)?, &open, &quit])?;
    let mut tray = TrayIconBuilder::with_id("airlock").tooltip("airlock: documents open in disposable VMs").menu(&menu);
    if let Some(icon) = app.default_window_icon() {
        tray = tray.icon(icon.clone());
    }
    tray.on_menu_event(|app, e| match e.id.as_ref() {
        "open" => {
            open_window(None);
        }
        "quit" => quit_all(app),
        _ => {}
    })
    .build(app)?;
    // Keep the count current.
    let handle = app.clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs(3));
        let label = open_count_label();
        let c = count.clone();
        if handle.run_on_main_thread(move || drop(c.set_text(label))).is_err() {
            return;
        }
    });
    Ok(())
}

/// One window shows the tray; the others wait to take over.
fn start_tray(app: &tauri::AppHandle) {
    if take_tray_lock() {
        if let Err(e) = build_tray(app) {
            log_event(&format!("tray icon unavailable: {e}"));
        }
        return;
    }
    let handle = app.clone();
    std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_secs(3));
        if take_tray_lock() {
            let h = handle.clone();
            let _ = handle.run_on_main_thread(move || {
                if let Err(e) = build_tray(&h) {
                    log_event(&format!("tray icon unavailable: {e}"));
                }
            });
            return;
        }
    });
}

/// Asks every other airlock window to close (SIGTERM, handled below), then closes this one.
fn quit_all(app: &tauri::AppHandle) {
    let me = std::process::id();
    for pid in instances().into_iter().filter(|&p| p != me) {
        terminate(pid);
    }
    shutdown(app);
}

/// Asks another airlock window to close properly (it handles SIGTERM).
#[cfg(unix)]
fn terminate(pid: u32) {
    unsafe { libc::kill(pid as i32, libc::SIGTERM) };
}

/// Windows: other windows are not found yet (instances() reads /proc).
#[cfg(not(unix))]
fn terminate(_pid: u32) {}

/// Closes this window's VM (deleting its copy of the document), then exits.
fn shutdown(app: &tauri::AppHandle) {
    let state = app.state::<AppState>();
    if let Some(d) = state.doc.lock().unwrap().take() {
        d.session.close();
    }
    app.exit(0);
}

#[cfg(unix)]
static TERM_PIPE: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);

#[cfg(unix)]
extern "C" fn on_term(_: libc::c_int) {
    // Only async-signal-safe work here: wake the thread below.
    let fd = TERM_PIPE.load(Ordering::SeqCst);
    unsafe { libc::write(fd, b"x".as_ptr().cast(), 1) };
}

/// SIGTERM (from "Close all", logout or `kill`) shuts this window down
/// properly instead of leaving its VM's run directory behind.
#[cfg(not(unix))]
fn handle_sigterm(_app: &tauri::AppHandle) {}

#[cfg(unix)]
fn handle_sigterm(app: &tauri::AppHandle) {
    let mut fds = [0; 2];
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return;
    }
    TERM_PIPE.store(fds[1], Ordering::SeqCst);
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_term as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
    }
    let handle = app.clone();
    std::thread::spawn(move || {
        let mut b = [0u8; 1];
        if unsafe { libc::read(fds[0], b.as_mut_ptr().cast(), 1) } == 1 {
            let h = handle.clone();
            let _ = handle.run_on_main_thread(move || shutdown(&h));
        }
    });
}
