//! Static look at the PDF's structure: which active-content features does it
//! carry, where do its links point, what does its JavaScript say. This runs
//! inside the VM because it parses hostile bytes. `mutool clean -d` (itself
//! monitored) normalises the file first: it decompresses streams, unpacks
//! object streams and decodes `#xx` name escapes, so obfuscated keys show up.

use crate::monitor::{self, Net};
use airlock_proto::Ind;
use std::time::Duration;

/// Counts `/Name` tokens that are not just a prefix of a longer name.
fn count_name(hay: &[u8], name: &[u8]) -> usize {
    let mut n = 0;
    let mut i = 0;
    while let Some(p) = hay[i..].windows(name.len()).position(|w| w == name) {
        let end = i + p + name.len();
        let next = hay.get(end).copied().unwrap_or(b' ');
        if !next.is_ascii_alphanumeric() {
            n += 1;
        }
        i = end;
    }
    n
}

/// Reads a PDF literal string `( ... )` starting at `s[0] == '('`.
fn literal(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let (mut depth, mut i) = (0, 0);
    while i < s.len() && out.len() < 512 * 1024 {
        let c = s[i];
        match c {
            b'\\' => {
                i += 1;
                if let Some(&e) = s.get(i) {
                    out.push(match e {
                        b'n' => b'\n',
                        b'r' => b'\r',
                        b't' => b'\t',
                        other => other,
                    });
                }
            }
            b'(' => {
                if depth > 0 {
                    out.push(c);
                }
                depth += 1;
            }
            b')' => {
                depth -= 1;
                if depth == 0 {
                    break;
                }
                out.push(c);
            }
            _ => out.push(c),
        }
        i += 1;
    }
    out
}

fn skip_ws(s: &[u8]) -> &[u8] {
    let n = s.iter().take_while(|c| c.is_ascii_whitespace()).count();
    &s[n..]
}

/// Value after a key: literal string, hex string, or the stream behind an
/// indirect reference `N G R`.
fn value_text(doc: &[u8], after_key: &[u8]) -> Option<Vec<u8>> {
    let v = skip_ws(after_key);
    match v.first()? {
        b'(' => Some(literal(v)),
        b'<' if v.get(1) != Some(&b'<') => {
            let end = v.iter().position(|&c| c == b'>')?;
            let hex: Vec<u8> = v[1..end].iter().copied().filter(|c| c.is_ascii_hexdigit()).collect();
            Some(hex.chunks(2).filter_map(|p| u8::from_str_radix(std::str::from_utf8(p).ok()?, 16).ok()).collect())
        }
        c if c.is_ascii_digit() => {
            let text = String::from_utf8_lossy(&v[..v.len().min(32)]);
            let mut it = text.split_whitespace();
            let (num, gen, r) = (it.next()?, it.next()?, it.next()?);
            if !r.starts_with('R') {
                return None;
            }
            let marker = format!("\n{num} {gen} obj");
            let at = doc.windows(marker.len()).position(|w| w == marker.as_bytes())?;
            let obj = &doc[at..];
            let s = obj.windows(6).position(|w| w == b"stream")? + 6;
            let e = obj.windows(9).position(|w| w == b"endstream")?;
            (s < e).then(|| skip_ws(&obj[s..e]).to_vec())
        }
        _ => None,
    }
}

fn one_line(b: &[u8], max: usize) -> String {
    let s: String = String::from_utf8_lossy(b)
        .chars()
        .map(|c| if c.is_whitespace() { ' ' } else { c })
        .collect();
    let s = s.split_whitespace().collect::<Vec<_>>().join(" ");
    s.chars().take(max).collect()
}

/// What the static pass found, plus the material the JS emulator needs.
/// One piece of the document's JavaScript and what makes a reader run it.
pub struct Script {
    /// Plain ASCII, e.g. "document opened (/OpenAction)".
    pub trigger: String,
    /// Runs without the reader clicking or typing anything.
    pub auto: bool,
    pub code: Vec<u8>,
}

pub struct Triage {
    pub indicators: Vec<(Ind, String)>,
    /// Automatic scripts first.
    pub scripts: Vec<Script>,
    /// Document info dictionary (malware hides payloads in /Subject etc.).
    pub info: Vec<(&'static str, Vec<u8>)>,
    /// (subject, contents) of annotations, read back via getAnnots().
    pub annots: Vec<(Vec<u8>, Vec<u8>)>,
}

/// The document with every stream's data left out (keywords kept): PDF
/// keys and actions live in dictionaries, so only these bytes are searched.
/// Image or font data can spell "/AA" or "/JS" by chance.
fn structure(doc: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(doc.len() / 4);
    let mut i = 0;
    while let Some(p) = doc[i..].windows(6).position(|w| w == b"stream") {
        let at = i + p;
        let kw_end = at + 6;
        // Data starts at ">> stream" + EOL (a stream dictionary's end). In
        // `mutool clean` output strings never hold a raw newline, so a
        // string cannot fake this to hide the keys after it.
        let after_dict = doc[..at].iter().rev().find(|c| !c.is_ascii_whitespace()) == Some(&b'>');
        let starts_data = after_dict && matches!(doc.get(kw_end), Some(b'\r' | b'\n'));
        if !starts_data {
            out.extend_from_slice(&doc[i..kw_end]);
            i = kw_end;
            continue;
        }
        out.extend_from_slice(&doc[i..kw_end]);
        out.push(b'\n');
        match doc[kw_end..].windows(9).position(|w| w == b"endstream") {
            Some(e) => i = kw_end + e,
            None => return out,
        }
    }
    out.extend_from_slice(&doc[i..]);
    out
}

/// All values of `key` (e.g. b"/Subj") in the document, in order. Keys are
/// searched in `hay` (the structure), references resolved in `doc`.
/// With `strings_only`, indirect references (e.g. a page's /Contents stream) are skipped.
fn values_of(doc: &[u8], hay: &[u8], key: &[u8], max: usize, strings_only: bool) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(p) = hay[i..].windows(key.len()).position(|w| w == key) {
        let at = i + p + key.len();
        i = at;
        if hay.get(at).is_some_and(|c| c.is_ascii_alphanumeric()) {
            continue;
        }
        if strings_only && !matches!(skip_ws(&hay[at..]).first(), Some(b'(' | b'<')) {
            continue;
        }
        if let Some(v) = value_text(doc, &hay[at..]) {
            out.push(v);
            if out.len() >= max {
                break;
            }
        }
    }
    out
}

/// Names whose escaping only makes sense to evade keyword scanners.
const KEYWORDS: &[&[u8]] = &[
    b"JavaScript", b"JS", b"OpenAction", b"AA", b"Launch", b"EmbeddedFile", b"EmbeddedFiles", b"URI", b"SubmitForm",
    b"ImportData", b"RichMedia", b"XFA", b"GoToR", b"GoToE", b"AcroForm", b"Names", b"ObjStm", b"Filter", b"Encrypt",
    b"FlateDecode", b"ASCIIHexDecode", b"ASCII85Decode", b"LZWDecode", b"RunLengthDecode", b"JBIG2Decode", b"Action", b"S",
];

/// Counts /Name tokens that contain #xx escapes and decode to a keyword.
fn escaped_keywords(raw: &[u8]) -> (usize, Vec<String>) {
    let delim = |c: u8| c.is_ascii_whitespace() || b"()<>[]{}/%".contains(&c);
    let (mut n, mut examples) = (0, Vec::new());
    let mut i = 0;
    while i < raw.len() {
        if raw[i] != b'/' {
            i += 1;
            continue;
        }
        let start = i + 1;
        let mut end = start;
        while end < raw.len() && end - start < 128 && !delim(raw[end]) {
            end += 1;
        }
        let tok = &raw[start..end];
        if tok.contains(&b'#') {
            let mut dec = Vec::with_capacity(tok.len());
            let mut k = 0;
            while k < tok.len() {
                let hex = |c: u8| (c as char).to_digit(16);
                match (tok[k], tok.get(k + 1).and_then(|&c| hex(c)), tok.get(k + 2).and_then(|&c| hex(c))) {
                    (b'#', Some(h), Some(l)) => {
                        dec.push((h * 16 + l) as u8);
                        k += 3;
                    }
                    (c, _, _) => {
                        dec.push(c);
                        k += 1;
                    }
                }
            }
            if KEYWORDS.contains(&dec.as_slice()) {
                n += 1;
                let shown = format!("/{}", String::from_utf8_lossy(&tok[..tok.len().min(40)]));
                if examples.len() < 3 && !examples.contains(&shown) {
                    examples.push(shown);
                }
            }
        }
        i = end.max(i + 1);
    }
    (n, examples)
}

const WALK_JS: &str = "/usr/lib/airlock/pdf_walk.js";

#[derive(Default)]
struct Walk {
    scripts: Vec<Script>,
    /// (trigger, automatic, action type, detail)
    actions: Vec<(String, bool, String, String)>,
    /// (name, size, first bytes)
    embedded: Vec<(String, u64, Vec<u8>)>,
    features: Vec<String>,
    /// (percent of the page, page, URI) of links covering much of a page
    big_links: Vec<(u32, u32, String)>,
}

fn unhex(h: &str) -> Option<Vec<u8>> {
    if h.len() % 2 != 0 {
        return None;
    }
    (0..h.len()).step_by(2).map(|i| u8::from_str_radix(h.get(i..i + 2)?, 16).ok()).collect()
}

fn label(s: &str, max: usize) -> String {
    s.chars().filter(|c| c.is_ascii_graphic() || *c == ' ').take(max).collect()
}

/// Runs guest/pdf_walk.js; None unless it got all the way through.
fn run_walker(pdf: &str, work: &str, out: &mut Vec<(Ind, String)>) -> Option<Walk> {
    let r = monitor::run(&["/usr/bin/mutool", "run", WALK_JS, pdf], work, &monitor::Opts::new(Net::Deny, Duration::from_secs(60)));
    out.extend(r.events);
    let text = String::from_utf8_lossy(r.stdout.as_deref()?).into_owned();
    if !text.lines().any(|l| l == "@@DONE") {
        return None;
    }
    let mut w = Walk { scripts: parse_scripts(text.as_bytes()), ..Default::default() };
    for line in text.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        match f[..] {
            ["@@ACT", trigger, auto, kind, detail] if w.actions.len() < 256 => {
                let detail = one_line(&utf16_to_utf8(&unhex(detail).unwrap_or_default()), 160);
                w.actions.push((label(trigger, 80), auto == "1", label(kind, 32), detail));
            }
            ["@@EMB", name, size, head] if w.embedded.len() < 64 => {
                let name = one_line(&utf16_to_utf8(&unhex(name).unwrap_or_default()), 100);
                w.embedded.push((name, size.parse().unwrap_or(0), unhex(head).unwrap_or_default()));
            }
            ["@@FEAT", feat] => w.features.push(label(feat, 16)),
            ["@@BIG", pct, page, uri] if w.big_links.len() < 20 => {
                let uri = one_line(&utf16_to_utf8(&unhex(uri).unwrap_or_default()), 200);
                w.big_links.push((pct.parse().unwrap_or(0).min(100), page.parse().unwrap_or(0), uri));
            }
            _ => {}
        }
    }
    Some(w)
}

/// What an embedded file really is, from its first bytes (then its name).
fn file_kind(name: &str, head: &[u8]) -> &'static str {
    let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    let program_ext = ["js", "jse", "vbs", "vbe", "wsf", "hta", "bat", "cmd", "ps1", "lnk", "scr", "exe", "dll", "jar", "msi", "com", "pif", "cpl", "reg"];
    if head.starts_with(b"MZ") {
        "Windows program"
    } else if head.starts_with(b"\x7fELF") {
        "Linux program"
    } else if head.starts_with(b"#!") {
        "script"
    } else if program_ext.contains(&ext.as_str()) {
        "program or script (by its name)"
    } else if head.starts_with(&[0xD0, 0xCF, 0x11, 0xE0]) {
        "Office document (older format; can carry macros)"
    } else if head.starts_with(b"PK\x03\x04") {
        if ["docx", "xlsx", "pptx", "docm", "xlsm", "pptm"].contains(&ext.as_str()) {
            "Office document"
        } else {
            "ZIP archive"
        }
    } else if head.starts_with(b"%PDF") {
        "PDF"
    } else if head.starts_with(b"{\\rt") {
        "RTF document"
    } else if head.starts_with(b"\x89PNG") || head.starts_with(b"\xff\xd8\xff") || head.starts_with(b"GIF8") {
        "image"
    } else if head.iter().all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace()) {
        "text or XML"
    } else {
        "data"
    }
}

/// Page navigation and display actions: nothing to report.
const QUIET_ACTIONS: &[&str] = &["GoTo", "GoToDp", "Thread", "Trans", "SetOCGState", "Hide", "ResetForm", "GoTo3DView"];
const QUIET_NAMED: &[&str] = &["NextPage", "PrevPage", "FirstPage", "LastPage", "GoBack", "GoForward", "FitPage", "FullScreen", "Find"];

fn report_walk(w: &Walk, out: &mut Vec<(Ind, String)>) {
    for f in &w.features {
        out.push(match f.as_str() {
            "Password" => (Ind::PdfUnreadable, "password protected: nothing in it can be checked (or shown) without the password".into()),
            "Encrypt" => (Ind::PdfFeature, "encryption (usually just permissions such as \"no printing\")".into()),
            "XFA" => (Ind::PdfFeature, "an XFA form (an older Adobe form technology; legitimate, but a past source of reader exploits)".into()),
            "RichMedia" => (Ind::PdfFeature, "rich media / Flash content".into()),
            "Media" => (Ind::PdfFeature, "embedded media (video or sound player)".into()),
            _ => continue,
        });
    }
    let mut links = Vec::new();
    for (trigger, auto, kind, detail) in &w.actions {
        if QUIET_ACTIONS.contains(&kind.as_str()) || (kind == "Named" && QUIET_NAMED.contains(&detail.as_str())) {
            continue;
        }
        // Clicked web links are ordinary links.
        if !auto && kind == "URI" {
            if !detail.is_empty() && !links.contains(detail) && links.len() < 20 {
                links.push(detail.clone());
            }
            continue;
        }
        let entry = (if *auto { Ind::PdfAutoAction } else { Ind::PdfClickAction }, format!("{kind}: {detail} [{trigger}]"));
        if !out.contains(&entry) && out.len() < 200 {
            out.push(entry);
        }
    }
    out.extend(links.into_iter().map(|u| (Ind::PdfUri, u)));
    // Only web addresses: a big link to a file next to the PDF is no lure.
    for (pct, page, uri) in w.big_links.iter().filter(|(_, _, u)| u.to_ascii_lowercase().starts_with("http")) {
        let entry = (Ind::PdfLure, format!("a link covers {pct}% of page {page}: {uri}"));
        if !out.contains(&entry) {
            out.push(entry);
        }
    }
    for (name, size, head) in &w.embedded {
        let name = if name.is_empty() { "(unnamed)" } else { name.as_str() };
        out.push((Ind::PdfAttachment, format!("{name} ({size} bytes, {})", file_kind(name, head))));
    }
}

/// What a run of bytes starts with, if it is a program or an archive.
fn payload_kind(b: &[u8]) -> Option<&'static str> {
    let magic: &[(&[u8], &str)] = &[
        (b"MZ", "Windows program"),
        (b"\x7fELF", "Linux program"),
        (b"PK\x03\x04", "ZIP archive"),
        (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
        (b"Rar!", "RAR archive"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "Office/OLE file"),
    ];
    magic.iter().find(|(m, _)| b.starts_with(m)).map(|(_, k)| *k)
}

/// Readers start at "%PDF-" (up to 1 KB in) and stop at the last "%%EOF":
/// whatever sits outside is invisible, and a classic hiding place. A PDF
/// that is also a program or archive (a polyglot) is how droppers smuggle one.
fn hidden_data(doc: &[u8], out: &mut Vec<(Ind, String)>) {
    if let Some(pos) = doc[..doc.len().min(1024)].windows(5).position(|w| w == b"%PDF-") {
        if pos > 0 {
            if let Some(kind) = payload_kind(doc) {
                out.push((Ind::HiddenData, format!("the file is also a {kind}: {pos} bytes come before the PDF begins (a polyglot)")));
            }
        }
    }
    let Some(eof) = doc.windows(5).rposition(|w| w == b"%%EOF") else { return };
    let tail = &doc[eof + 5..];
    let start = tail.iter().position(|b| !b" \t\r\n\x00".contains(b)).unwrap_or(tail.len());
    let tail = &tail[start..];
    // A ZIP's index at the end makes the same file a ZIP archive too.
    if tail.windows(4).any(|w| w == b"PK\x05\x06" || w == b"PK\x01\x02") {
        out.push((Ind::HiddenData, format!("{} bytes after the end of the PDF, containing a ZIP archive's index: the file is also a ZIP archive (a polyglot)", tail.len())));
        return;
    }
    let lower: Vec<u8> = tail[..tail.len().min(4096)].to_ascii_lowercase();
    if tail.len() > 64 && (lower.windows(5).any(|w| w == b"<html") || lower.windows(7).any(|w| w == b"<script")) {
        out.push((Ind::HiddenData, format!("{} bytes after the end of the PDF, containing a web page: renamed to .html it becomes a page with scripts (a polyglot)", tail.len())));
        return;
    }
    if tail.len() > 1024 {
        // A payload may start right away or after some padding.
        let kind = (0..tail.len().min(4096)).find_map(|i| payload_kind(&tail[i..]).filter(|k| !k.starts_with("Windows") || tail[i..].windows(4).take(1024).any(|w| w == b"PE\0\0")));
        out.push((
            Ind::HiddenData,
            match kind {
                Some(k) => format!("{} bytes after the end of the PDF, containing a {k} (a polyglot)", tail.len()),
                None => format!("{} bytes after the end of the PDF that no reader shows", tail.len()),
            },
        ));
    }
}

/// Fallback when MuPDF cannot walk the document: name counts on the structure.
fn byte_scan(doc: &[u8], st: &[u8], out: &mut Vec<(Ind, String)>) {
    let js = count_name(st, b"/JavaScript") + count_name(st, b"/JS");
    if js > 0 {
        out.push((Ind::PdfFeature, format!("JavaScript ({js} places)")));
    }
    let features: &[(&[u8], &str)] = &[
        (b"/OpenAction", "an action that runs on open (/OpenAction)"),
        (b"/AA", "automatic actions (/AA)"),
        (b"/Launch", "a Launch action that can start programs"),
        (b"/SubmitForm", "a form that submits data (/SubmitForm)"),
        (b"/ImportData", "an action that imports external data"),
        (b"/EmbeddedFile", "an embedded file"),
        (b"/RichMedia", "rich media / Flash"),
        (b"/XFA", "an XFA form"),
        (b"/GoToR", "a link that opens another document (/GoToR)"),
        (b"/GoToE", "a link that opens an embedded document (/GoToE)"),
    ];
    for (name, label) in features {
        let n = count_name(st, name);
        if n > 0 {
            out.push((Ind::PdfFeature, if n > 1 { format!("{label} x{n}") } else { label.to_string() }));
        }
    }
    let mut uris = Vec::new();
    let mut i = 0;
    while let Some(p) = st[i..].windows(4).position(|w| w == b"/URI") {
        let at = i + p + 4;
        if let Some(v) = value_text(doc, &st[at..]) {
            let u = one_line(&v, 200);
            if !u.is_empty() && !uris.contains(&u) && uris.len() < 20 {
                uris.push(u);
            }
        }
        i = at;
    }
    out.extend(uris.into_iter().map(|u| (Ind::PdfUri, u)));
}

/// Only calls to Adobe's built-in form helpers (AFNumber_Format(2, 0, ...);
/// AFSimple_Calculate("SUM", ...)): what every fillable form uses.
fn standard_form_script(code: &[u8]) -> Option<Vec<String>> {
    let text = String::from_utf8_lossy(code);
    let mut names = Vec::new();
    for stmt in text.split([';', '\n', '\r']).map(str::trim).filter(|s| !s.is_empty()) {
        let open = stmt.find('(')?;
        let name = stmt[..open].trim();
        let ok = name.starts_with("AF") && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') && stmt.ends_with(')');
        if !ok || stmt[open..].contains(['{', '}', '=']) {
            return None;
        }
        names.push(name.to_string());
    }
    (!names.is_empty()).then_some(names)
}

fn report_scripts(scripts: &[Script], out: &mut Vec<(Ind, String)>) {
    let (mut form, mut form_names) = (0, Vec::<String>::new());
    let (mut shown_auto, mut shown_click) = (0, 0);
    for js in scripts {
        if let Some(names) = standard_form_script(&js.code) {
            form += 1;
            for n in names {
                if !form_names.contains(&n) && form_names.len() < 6 {
                    form_names.push(n);
                }
            }
            continue;
        }
        let text = format!("[{}] {}", js.trigger, one_line(&js.code, 160));
        if js.auto && shown_auto < 5 {
            shown_auto += 1;
            out.push((Ind::PdfJs, text));
        } else if !js.auto && shown_click < 5 {
            shown_click += 1;
            out.push((Ind::PdfJsClick, text));
        }
    }
    if form > 0 {
        out.push((Ind::PdfJsForm, format!("{form} form-field script(s) that only use Adobe's standard formatting functions ({})", form_names.join(", "))));
    }
}

/// Lines "@@JS\t<trigger>\t<0|1>\t<hex>" from pdf_walk.js.
fn parse_scripts(out: &[u8]) -> Vec<Script> {
    let mut v: Vec<Script> = Vec::new();
    for line in String::from_utf8_lossy(out).lines() {
        let mut f = line.splitn(4, '\t');
        let (Some("@@JS"), Some(trigger), Some(auto), Some(hex)) = (f.next(), f.next(), f.next(), f.next()) else { continue };
        if hex.len() % 2 != 0 || v.len() >= 64 {
            continue;
        }
        let Some(code) = (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok()).collect::<Option<Vec<u8>>>() else { continue };
        let code = utf16_to_utf8(&code);
        if trimmed(&code).is_empty() || v.iter().any(|s| s.code == code) {
            continue;
        }
        let trigger: String = trigger.chars().filter(|c| c.is_ascii_graphic() || *c == ' ').take(80).collect();
        v.push(Script { trigger, auto: auto == "1", code });
    }
    v
}

/// PDF text strings may be UTF-16BE with a byte-order mark.
fn utf16_to_utf8(b: &[u8]) -> Vec<u8> {
    match b {
        [0xFE, 0xFF, rest @ ..] => {
            let units: Vec<u16> = rest.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect();
            String::from_utf16_lossy(&units).into_bytes()
        }
        _ => b.to_vec(),
    }
}

fn trimmed(b: &[u8]) -> &[u8] {
    let start = b.iter().position(|c| !c.is_ascii_whitespace()).unwrap_or(b.len());
    let end = b.iter().rposition(|c| !c.is_ascii_whitespace()).map_or(start, |e| e + 1);
    &b[start..end]
}

pub fn analyze(raw: &[u8], work: &str, doc_path: &str) -> Triage {
    let mut out = Vec::new();
    let clean_path = format!("{work}/clean.pdf");
    let r = monitor::run(&["/usr/bin/mutool", "clean", "-d", doc_path, &clean_path], work, &monitor::Opts::new(Net::Deny, Duration::from_secs(60)));
    out.extend(r.events);
    let clean = std::fs::read(&clean_path).unwrap_or_default();
    let doc: &[u8] = if clean.is_empty() { raw } else { &clean };
    let st = structure(doc);

    // The PDF's real structure, read by MuPDF (in here, as nobody): every
    // action with what triggers it, embedded files, risky features.
    let mut walk = run_walker(doc_path, work, &mut out);
    if walk.is_none() && !clean.is_empty() {
        walk = run_walker(&clean_path, work, &mut out);
    }
    let walked = walk.is_some();
    let walk = walk.unwrap_or_default();
    // The original bytes: cleaning drops whatever sits outside the PDF.
    hidden_data(raw, &mut out);
    if walked {
        report_walk(&walk, &mut out);
    } else {
        out.push((Ind::PdfUnreadable, "MuPDF could not read the document's structure (damaged, or malformed on purpose); a rough byte scan was used instead".into()));
        byte_scan(doc, &st, &mut out);
    }

    // Scripts the walk could not place (byte scan of the structure): they
    // are not attached to anything a reader runs.
    let mut scripts = walk.scripts;
    for v in values_of(doc, &st, b"/JS", 32, false) {
        let code = utf16_to_utf8(&v);
        let key = trimmed(&code);
        if key.is_empty() || scripts.iter().any(|s| trimmed(&s.code) == key) {
            continue;
        }
        // Still-compressed or binary data under a /JS key is not a script
        // (random bytes are ~12% control characters, text has next to none).
        let control = key.iter().filter(|&&c| (c < 0x20 && !c.is_ascii_whitespace()) || c == 0x7f).count();
        if control * 20 > key.len() {
            continue;
        }
        let (trigger, auto) = if walked { ("not attached to any trigger", false) } else { ("unknown trigger", true) };
        scripts.push(Script { trigger: trigger.into(), auto, code });
    }
    scripts.sort_by_key(|s| !s.auto);
    report_scripts(&scripts, &mut out);
    let info = ["Title", "Author", "Subject", "Keywords", "Creator", "Producer"]
        .into_iter()
        .filter_map(|k| values_of(doc, &st, format!("/{k}").as_bytes(), 1, false).pop().map(|v| (k, v)))
        .collect();
    let subj = values_of(doc, &st, b"/Subj", 20, true);
    let contents = values_of(doc, &st, b"/Contents", 20, true);
    let annots = subj.into_iter().zip(contents.into_iter().chain(std::iter::repeat(Vec::new()))).collect();

    // Obfuscation: security-relevant names written with #xx escapes
    // (/J#61vaScript). Escapes elsewhere are normal (font names with
    // spaces or non-Latin characters: /Times#20New#20Roman).
    let (hidden, examples) = escaped_keywords(raw);
    if hidden > 0 {
        out.push((Ind::PdfObfuscation, format!("hex-escaped keywords x{hidden} ({}) hide them from scanners", examples.join(", "))));
    }
    for kw in [&b"/JavaScript"[..], b"/OpenAction", b"/Launch"] {
        if count_name(raw, kw) == 0 && count_name(&st, kw) > 0 {
            let k = String::from_utf8_lossy(&kw[1..]).into_owned();
            out.push((Ind::PdfObfuscation, format!("{k} only visible after decompression (hidden from naive scanners)")));
        }
    }
    Triage { indicators: out, scripts, info, annots }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structure_skips_stream_data_only() {
        let doc = b"1 0 obj\n<< /Length 9 >>\nstream\nxx/AA /JS\nendstream\nendobj\n2 0 obj\n<< /AA 3 0 R /S (stream) >>\nendobj\n";
        let st = structure(doc);
        assert_eq!(count_name(&st, b"/AA"), 1, "{}", String::from_utf8_lossy(&st));
        assert_eq!(count_name(&st, b"/JS"), 0);
        assert!(st.ends_with(b"/S (stream) >>\nendobj\n"));
    }
}
