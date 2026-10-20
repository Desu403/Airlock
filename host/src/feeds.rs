//! The malware data airlock checks against, refreshed in the background:
//! the same three feeds as scripts/known-malware.sh and scripts/clamav-db.sh,
//! in Rust so Windows (which has none of those tools) gets them too.
//!
//!  * known-malware.bin: MalwareBazaar's SHA-256 list (abuse.ch), sorted
//!    32-byte records; the full list every 3 days, the last hours' additions
//!    in between. known-malware.info: "updated <unix time> count <n>".
//!  * urlhaus.txt: web addresses spreading malware right now (URLhaus).
//!  * clamav/: ClamAV's signed database (Cisco Talos), fetched only when
//!    changed and at most every 12 hours, packed into clamav.sqfs: the
//!    read-only disk the ClamAV VM mounts (squashfs: no mke2fs needed).
//!    clamav.status: "<unix time> ok|refused|missing".
//!
//! A failed download keeps what is there. Nothing about the user's files is
//! sent anywhere: these are plain downloads of public lists.

use anyhow::{bail, Context, Result};
use std::fs;
use std::io::Read;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const BAZAAR_FULL: &str = "https://bazaar.abuse.ch/export/txt/sha256/full/";
const BAZAAR_RECENT: &str = "https://bazaar.abuse.ch/export/txt/sha256/recent/";
const URLHAUS: &str = "https://urlhaus.abuse.ch/downloads/text_online/";
const CLAMAV: &str = "https://database.clamav.net";
/// ClamAV's mirror serves clients that say they are ClamAV.
const CLAMAV_UA: &str = "ClamAV/1.4.6 (OS: windows, ARCH: x86_64, CPU: x86_64; airlock)";
const FULL_EVERY: u64 = 3 * 86400;
const CLAMAV_EVERY: u64 = 12 * 3600;

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new().timeout_connect(Duration::from_secs(20)).timeout(Duration::from_secs(600)).build()
}

fn read_all(r: ureq::Response, limit: u64) -> Result<Vec<u8>> {
    let mut v = Vec::new();
    r.into_reader().take(limit).read_to_end(&mut v)?;
    Ok(v)
}

/// Replaces `path` atomically with `data`.
fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("new");
    fs::write(&tmp, data)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

/// Everything due, each step on its own (one failing does not stop the
/// others). Returns one line per step, for the log.
pub fn refresh(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    match known_malware(dir) {
        Ok(s) => out.push(s),
        Err(e) => out.push(format!("known-malware list not refreshed: {e:#}")),
    }
    match urlhaus(dir) {
        Ok(s) => out.push(s),
        Err(e) => out.push(format!("malware-site list not refreshed: {e:#}")),
    }
    match clamav(dir, false) {
        Ok(s) => out.push(s),
        Err(e) => out.push(format!("ClamAV database not refreshed: {e:#}")),
    }
    out
}

fn sha256s(text: &[u8]) -> impl Iterator<Item = [u8; 32]> + '_ {
    text.split(|&b| b == b'\n').filter_map(|l| {
        let l = l.strip_suffix(b"\r").unwrap_or(l);
        if l.len() != 64 {
            return None;
        }
        let mut h = [0u8; 32];
        for (i, pair) in l.chunks(2).enumerate() {
            h[i] = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
        }
        Some(h)
    })
}

pub fn known_malware(dir: &Path) -> Result<String> {
    let bin = dir.join("known-malware.bin");
    let info = dir.join("known-malware.info");
    let updated: u64 = fs::read_to_string(&info).ok().and_then(|s| s.split_whitespace().nth(1)?.parse().ok()).unwrap_or(0);
    let full = !bin.exists() || now().saturating_sub(updated) > FULL_EVERY;
    let mut set: std::collections::BTreeSet<[u8; 32]> = Default::default();
    if full {
        let zip = read_all(agent().get(BAZAAR_FULL).call()?, 512 << 20)?;
        let mut z = zip::ZipArchive::new(std::io::Cursor::new(zip)).context("MalwareBazaar's list is not a zip")?;
        if z.len() != 1 {
            bail!("MalwareBazaar's zip has {} files, expected 1", z.len());
        }
        let mut text = Vec::new();
        z.by_index(0)?.take(1 << 30).read_to_end(&mut text)?;
        set.extend(sha256s(&text.to_ascii_lowercase()));
        if set.len() < 100_000 {
            bail!("the full list has only {} entries; keeping the current one", set.len());
        }
    } else {
        let text = read_all(agent().get(BAZAAR_RECENT).call()?, 64 << 20)?;
        set.extend(sha256s(&text.to_ascii_lowercase()));
        let old = fs::read(&bin).unwrap_or_default();
        set.extend(old.chunks_exact(32).map(|c| <[u8; 32]>::try_from(c).unwrap()));
    }
    let data: Vec<u8> = set.iter().flatten().copied().collect();
    write_atomic(&bin, &data)?;
    // A merge keeps the full list's date (the next full refresh is due from it).
    let stamp = if full || updated == 0 { now() } else { updated };
    write_atomic(&info, format!("updated {stamp} count {}\n", set.len()).as_bytes())?;
    Ok(format!("known malware: {} fingerprints ({})", set.len(), if full { "full list" } else { "recent additions" }))
}

pub fn urlhaus(dir: &Path) -> Result<String> {
    let text = read_all(agent().get(URLHAUS).call()?, 64 << 20)?;
    let text = String::from_utf8_lossy(&text);
    let mut urls: Vec<&str> = text.lines().map(str::trim).filter(|l| l.starts_with("http://") || l.starts_with("https://")).collect();
    urls.sort_unstable();
    urls.dedup();
    if urls.len() <= 1000 {
        bail!("only {} addresses; keeping the current list", urls.len());
    }
    write_atomic(&dir.join("urlhaus.txt"), (urls.join("\n") + "\n").as_bytes())?;
    Ok(format!("malware sites: {} addresses", urls.len()))
}

/// ClamAV's database. `pack_only`: no downloads, just (re)build
/// clamav.sqfs from the files in clamav/ (scripts/windows.sh).
pub fn clamav(dir: &Path, pack_only: bool) -> Result<String> {
    let db = dir.join("clamav");
    let status = dir.join("clamav.status");
    let image = dir.join("clamav.sqfs");
    fs::create_dir_all(&db)?;
    let last: u64 = fs::read_to_string(&status).ok().and_then(|s| s.split_whitespace().next()?.parse().ok()).unwrap_or(0);
    let mut changed = !image.exists();
    let mut refused = false;
    if !pack_only {
        if image.exists() && now().saturating_sub(last) < CLAMAV_EVERY {
            return Ok("ClamAV database: checked less than 12 hours ago".into());
        }
        for f in ["main.cvd", "daily.cvd", "bytecode.cvd"] {
            let path = db.join(f);
            let mut req = agent().get(&format!("{CLAMAV}/{f}")).set("User-Agent", CLAMAV_UA);
            // Only when newer than the copy we have (a "not changed" answer is tiny).
            if let Ok(t) = fs::metadata(&path).and_then(|m| m.modified()) {
                req = req.set("If-Modified-Since", &httpdate::fmt_http_date(t));
            }
            match req.call() {
                Ok(r) => {
                    let data = read_all(r, 1 << 30)?;
                    // A .cvd starts with "ClamAV-VDB:"; anything else (an error page) is dropped.
                    if data.starts_with(b"ClamAV-VDB:") {
                        write_atomic(&path, &data)?;
                        changed = true;
                    }
                }
                Err(ureq::Error::Status(304, _)) => {}
                Err(ureq::Error::Status(429, _)) => refused = true,
                Err(e) => return Err(e.into()),
            }
        }
    }
    if !db.join("main.cvd").exists() || !db.join("daily.cvd").exists() {
        let _ = fs::write(&status, format!("{} missing\n", now()));
        bail!("ClamAV database not available");
    }
    if !pack_only {
        let _ = fs::write(&status, format!("{} {}\n", now(), if refused { "refused" } else { "ok" }));
    }
    if changed || pack_only {
        pack_sqfs(&db, &image)?;
        // The version line, for About (the .cvd files may not be shipped).
        let mut head = Vec::new();
        fs::File::open(db.join("daily.cvd"))?.take(512).read_to_end(&mut head)?;
        write_atomic(&dir.join("clamav.daily-header"), &head)?;
    }
    let daily = fs::File::open(db.join("daily.cvd")).and_then(|f| {
        let mut h = Vec::new();
        f.take(160).read_to_end(&mut h)?;
        Ok(h)
    });
    let version = daily.ok().and_then(|h| String::from_utf8_lossy(&h).split(':').nth(2).map(str::to_owned)).unwrap_or_default();
    Ok(format!("ClamAV database: {version} (daily version){}", if refused { "; the server refused a download (busy), the current one stays" } else { "" }))
}

/// The database files as a squashfs image (gzip; the guest kernel reads it).
/// The signatures are verified by ClamAV itself when it loads them.
fn pack_sqfs(db: &Path, image: &Path) -> Result<()> {
    use backhand::compression::Compressor;
    use backhand::{FilesystemCompressor, FilesystemWriter, NodeHeader};
    let header = NodeHeader { permissions: 0o444, uid: 0, gid: 0, mtime: 0 };
    let mut names: Vec<_> = fs::read_dir(db)?.flatten().map(|e| e.file_name()).filter(|n| n.to_string_lossy().ends_with(".cvd")).collect();
    names.sort();
    let mut files = Vec::new();
    for n in &names {
        files.push((n.to_string_lossy().into_owned(), fs::File::open(db.join(n))?));
    }
    // Declared after the files: it borrows them until it is written.
    let mut fsw = FilesystemWriter::default();
    // gzip: built without C libraries (cross-builds for Windows).
    fsw.set_compressor(FilesystemCompressor::new(Compressor::Gzip, None).context("gzip compressor")?);
    // Readable by the unprivileged scanner inside the VM.
    fsw.set_root_mode(0o755);
    for (name, f) in files.iter_mut() {
        fsw.push_file(std::io::BufReader::new(f), name.as_str(), header).with_context(|| format!("adding {name}"))?;
    }
    let tmp = image.with_extension("sqfs.new");
    let mut out = fs::File::create(&tmp)?;
    fsw.write(&mut out).context("writing the squashfs image")?;
    drop(out);
    fs::rename(&tmp, image)?;
    Ok(())
}
