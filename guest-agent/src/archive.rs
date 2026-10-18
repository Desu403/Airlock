//! Archives (ZIP, 7z, RAR, TAR, GZ/BZ2/XZ, ISO, CAB): listed with 7-Zip inside
//! the VM and shown as a contents page. A file inside is opened in a fresh VM
//! of its own: that VM gets the whole archive and unpacks just that one file
//! (kernel option airlock.entry=N). Nothing is ever unpacked on the host.

use crate::monitor::{self, Net, Opts};
use airlock_proto::{Ind, MAX_DOC_BYTES};
use std::time::Duration;

const SEVENZIP: &str = "/usr/bin/7zz";
const TIMEOUT: Duration = Duration::from_secs(60);
/// Bigger listings are cut (noted on the contents page).
pub const MAX_ENTRIES: usize = 2000;
/// 7-Zip never waits for a password: locked files fail instead.
const NO_PASSWORD: &str = "-pairlock-no-password";

pub struct Entry {
    pub path: String,
    pub size: u64,
    pub encrypted: bool,
    pub dir: bool,
}

/// Archive formats by their first bytes.
pub fn kind(doc: &[u8]) -> Option<&'static str> {
    let at = |off: usize, magic: &[u8]| doc.len() >= off + magic.len() && &doc[off..off + magic.len()] == magic;
    if at(0, b"PK\x03\x04") || at(0, b"PK\x05\x06") {
        Some("zip")
    } else if at(0, b"7z\xBC\xAF\x27\x1C") {
        Some("7z")
    } else if at(0, b"Rar!\x1A\x07") {
        Some("rar")
    } else if at(257, b"ustar") {
        Some("tar")
    } else if at(0, &[0x1F, 0x8B]) {
        Some("gz")
    } else if at(0, b"BZh") && doc.len() > 4 && (b'1'..=b'9').contains(&doc[3]) {
        Some("bz2")
    } else if at(0, &[0xFD, b'7', b'z', b'X', b'Z', 0]) {
        Some("xz")
    } else if at(0, b"MSCF") {
        Some("cab")
    } else if at(0x8001, b"CD001") || at(0x8801, b"CD001") || at(0x9001, b"CD001") {
        Some("iso")
    } else {
        None
    }
}

/// `7zz l -slt`: one "Key = value" block per file.
pub fn list(path: &str, work: &str, net: Net) -> (Vec<(Ind, String)>, Vec<Entry>) {
    let r = monitor::run(&[SEVENZIP, "l", "-slt", "-ba", NO_PASSWORD, path], work, &Opts::new(net, TIMEOUT));
    let text = String::from_utf8_lossy(&r.stdout.unwrap_or_default()).into_owned();
    let mut entries = Vec::new();
    let mut cur: Option<Entry> = None;
    for line in text.lines().chain(std::iter::once("")) {
        if line.trim().is_empty() {
            if let Some(e) = cur.take() {
                if !e.path.is_empty() && entries.len() < MAX_ENTRIES {
                    entries.push(e);
                }
            }
            continue;
        }
        let (k, v) = line.split_once(" = ").unwrap_or((line, ""));
        let e = cur.get_or_insert(Entry { path: String::new(), size: 0, encrypted: false, dir: false });
        match k {
            "Path" => e.path = v.to_string(),
            "Size" => e.size = v.parse().unwrap_or(0),
            "Encrypted" => e.encrypted = v == "+",
            "Folder" => e.dir = v == "+",
            "Attributes" => e.dir |= v.starts_with('D'),
            _ => {}
        }
    }
    (r.events, entries)
}

/// The files, folders left out (they are opened by their files).
pub fn files(entries: &[Entry]) -> Vec<&Entry> {
    entries.iter().filter(|e| !e.dir).collect()
}

/// One file unpacked inside this VM (by its exact path: no wildcards).
pub fn extract(path: &str, entry: &str, work: &str, net: Net) -> (Vec<(Ind, String)>, Option<Vec<u8>>) {
    let r = monitor::run(&[SEVENZIP, "e", "-so", "-spd", NO_PASSWORD, path, entry], work, &Opts::new(net, TIMEOUT));
    let bytes = r.stdout.filter(|b| !b.is_empty() && b.len() as u64 <= MAX_DOC_BYTES);
    (r.events, bytes)
}

/// Extensions that run when double-clicked on Windows, or mount as a drive.
const RISKY: &[&str] = &[
    "exe", "scr", "com", "pif", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "ps1", "psm1", "lnk", "msi", "msix", "appx", "jar",
    "dll", "cpl", "reg", "iso", "img", "vhd", "vhdx", "chm", "url", "application", "appref-ms", "sct", "xll", "library-ms", "search-ms",
];
const DOCUMENTS: &[&str] = &["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "txt", "jpg", "jpeg", "png", "zip", "rar", "odt", "csv"];

/// Plain words about a file name: "program", "disguised", "locked".
pub fn flags(e: &Entry) -> Vec<&'static str> {
    let name = e.path.rsplit(['/', '\\']).next().unwrap_or(&e.path).to_ascii_lowercase();
    let parts: Vec<&str> = name.split('.').collect();
    let mut out = Vec::new();
    if parts.len() >= 2 && RISKY.contains(&parts[parts.len() - 1]) {
        out.push("program");
        // "invoice.pdf.exe", or a document name padded with spaces before ".exe".
        if parts.len() >= 3 && DOCUMENTS.contains(&parts[parts.len() - 2].trim()) || name.contains("   ") {
            out.push("disguised");
        }
    }
    if e.encrypted {
        out.push("locked");
    }
    out
}

/// What the archive itself says, before anything inside is looked at.
pub fn findings(entries: &[Entry], kind: &str) -> Vec<(Ind, String)> {
    let mut out = Vec::new();
    for e in files(entries) {
        let f = flags(e);
        if f.contains(&"disguised") {
            out.push((Ind::Script, format!("archive-disguised: {} (a program named like a document)", e.path)));
        } else if f.contains(&"program") {
            out.push((Ind::Script, format!("archive-program: {}", e.path)));
        }
    }
    let locked = files(entries).iter().filter(|e| e.encrypted).count();
    if locked > 0 {
        out.push((Ind::Script, format!("archive-locked: {locked} file(s) locked with a password in the {kind} archive could not be checked")));
    }
    out
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

fn human(n: u64) -> String {
    match n {
        n if n >= 1 << 30 => format!("{:.1} GB", n as f64 / (1u64 << 30) as f64),
        n if n >= 1 << 20 => format!("{:.1} MB", n as f64 / (1u64 << 20) as f64),
        n if n >= 1 << 10 => format!("{:.0} KB", n as f64 / 1024.0),
        n => format!("{n} B"),
    }
}

/// The contents page: one row per file, warnings first; -> `<work>/archive.pdf`.
pub fn page(entries: &[Entry], kind: &str, work: &str, net: Net) -> (Vec<(Ind, String)>, Option<String>) {
    let files = files(entries);
    let total: u64 = files.iter().map(|e| e.size).sum();
    let mut rows = String::new();
    for (i, e) in files.iter().enumerate() {
        let f = flags(e);
        let tag = if f.contains(&"disguised") {
            "<span class=\"bad\">disguised program</span>"
        } else if f.contains(&"program") {
            "<span class=\"warn\">program</span>"
        } else if f.contains(&"locked") {
            "<span class=\"warn\">locked</span>"
        } else {
            ""
        };
        rows.push_str(&format!("<tr><td class=\"n\">{}</td><td>{}</td><td class=\"s\">{}</td><td>{tag}</td></tr>\n", i + 1, esc(&e.path), human(e.size)));
    }
    let more = if entries.len() >= MAX_ENTRIES { format!("<p class=\"note\">Only the first {MAX_ENTRIES} entries are listed.</p>") } else { String::new() };
    let xhtml = format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<html xmlns=\"http://www.w3.org/1999/xhtml\"><head><title>Archive</title><style>\
         html, body {{ background: #0b1114; }} body {{ margin: 0; color: #d8e2e4; font-family: \"DejaVu Sans\", sans-serif; font-size: 9pt; }}\
         h1 {{ font-size: 13pt; margin: 0 0 2pt; color: #fff; }} p.sub {{ margin: 0 0 12pt; color: #7f9a9b; }}\
         table {{ border-collapse: collapse; width: 100%; }} td {{ padding: 3pt 6pt; border-bottom: 1px solid #1a2a2e; vertical-align: top; }}\
         td.n {{ color: #4d6266; text-align: right; width: 24pt; }} td.s {{ color: #7f9a9b; text-align: right; white-space: nowrap; }}\
         .bad {{ color: #fb7185; font-weight: bold; }} .warn {{ color: #fcd34d; }} .note {{ color: #7f9a9b; margin-top: 10pt; }}\
         </style></head><body><h1>{} archive · {} file(s) · {}</h1><p class=\"sub\">Listed inside the VM. Open a file from the side panel: it opens in a fresh VM of its own, and nothing is unpacked on your computer.</p>\
         <table>{rows}</table>{more}</body></html>\n",
        kind.to_ascii_uppercase(),
        files.len(),
        human(total)
    );
    let src = format!("{work}/archive.xhtml");
    if std::fs::write(&src, xhtml).is_err() {
        return (Vec::new(), None);
    }
    let pdf = format!("{work}/archive.pdf");
    let r = monitor::run(&["/usr/bin/mutool", "convert", "-W", "595", "-H", "842", "-o", &pdf, &src], work, &Opts::new(net, TIMEOUT));
    let ok = std::path::Path::new(&pdf).exists();
    (r.events, ok.then_some(pdf))
}

/// For the host's file list (Cmd::Entries): "index size flags name", flags
/// comma-separated or "-" (the text sanitiser keeps only spaces and newlines).
pub fn listing(entries: &[Entry]) -> String {
    files(entries)
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let f = flags(e);
            format!("{i} {} {} {}", e.size, if f.is_empty() { "-".into() } else { f.join(",") }, e.path.replace(['\t', '\n', '\r'], " "))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn names() {
        let e = |p: &str| Entry { path: p.into(), size: 1, encrypted: false, dir: false };
        assert_eq!(flags(&e("report.pdf")), Vec::<&str>::new());
        assert_eq!(flags(&e("setup.exe")), ["program"]);
        assert_eq!(flags(&e("Invoice_2026.pdf.exe")), ["program", "disguised"]);
        assert_eq!(flags(&e("dir/Scan.docx.js")), ["program", "disguised"]);
        assert_eq!(kind(b"7z\xBC\xAF\x27\x1C\0\x04"), Some("7z"));
        assert_eq!(kind(b"Rar!\x1A\x07\x01\0"), Some("rar"));
        assert_eq!(kind(b"%PDF-1.7"), None);
    }
}
