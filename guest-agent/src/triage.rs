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

/// All values of `key` (e.g. b"/Subj") in the document, in order.
/// With `strings_only`, indirect references (e.g. a page's /Contents stream) are skipped.
fn values_of(doc: &[u8], key: &[u8], max: usize, strings_only: bool) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0;
    while let Some(p) = doc[i..].windows(key.len()).position(|w| w == key) {
        let at = i + p + key.len();
        i = at;
        if doc.get(at).is_some_and(|c| c.is_ascii_alphanumeric()) {
            continue;
        }
        if strings_only && !matches!(skip_ws(&doc[at..]).first(), Some(b'(' | b'<')) {
            continue;
        }
        if let Some(v) = value_text(doc, &doc[at..]) {
            out.push(v);
            if out.len() >= max {
                break;
            }
        }
    }
    out
}

const SCRIPTS_JS: &str = "/usr/lib/airlock/pdf_scripts.js";

/// Lines "@@JS\t<trigger>\t<0|1>\t<hex>" from pdf_scripts.js.
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

    let js = count_name(doc, b"/JavaScript") + count_name(doc, b"/JS");
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
        (b"/Encrypt", "encryption"),
    ];
    for (name, label) in features {
        let n = count_name(doc, name);
        if n > 0 {
            out.push((Ind::PdfFeature, if n > 1 { format!("{label} x{n}") } else { label.to_string() }));
        }
    }

    // Link targets.
    let mut uris = Vec::new();
    let mut i = 0;
    while let Some(p) = doc[i..].windows(4).position(|w| w == b"/URI") {
        let at = i + p + 4;
        if let Some(v) = value_text(doc, &doc[at..]) {
            let u = one_line(&v, 200);
            if !u.is_empty() && !uris.contains(&u) && uris.len() < 20 {
                uris.push(u);
            }
        }
        i = at;
    }
    out.extend(uris.into_iter().map(|u| (Ind::PdfUri, u)));

    // JavaScript with its triggers, from the object graph (MuPDF, in here);
    // a byte scan backs it up so nothing it cannot place is skipped.
    let src = if clean.is_empty() { doc_path } else { clean_path.as_str() };
    let r = monitor::run(&["/usr/bin/mutool", "run", SCRIPTS_JS, src], work, &monitor::Opts::new(Net::Deny, Duration::from_secs(60)));
    out.extend(r.events);
    let walked = r.stdout.is_some();
    let mut scripts = r.stdout.as_deref().map(parse_scripts).unwrap_or_default();
    for v in values_of(doc, b"/JS", 32, false) {
        let code = utf16_to_utf8(&v);
        let key = trimmed(&code);
        if key.is_empty() || scripts.iter().any(|s| trimmed(&s.code) == key) {
            continue;
        }
        let (trigger, auto) = if walked { ("not attached to any trigger", false) } else { ("unknown trigger", true) };
        scripts.push(Script { trigger: trigger.into(), auto, code });
    }
    scripts.sort_by_key(|s| !s.auto);
    for js in scripts.iter().take(5) {
        out.push((Ind::PdfJs, format!("[{}] {}", js.trigger, one_line(&js.code, 160))));
    }
    let info = ["Title", "Author", "Subject", "Keywords", "Creator", "Producer"]
        .into_iter()
        .filter_map(|k| values_of(doc, format!("/{k}").as_bytes(), 1, false).pop().map(|v| (k, v)))
        .collect();
    let subj = values_of(doc, b"/Subj", 20, true);
    let contents = values_of(doc, b"/Contents", 20, true);
    let annots = subj.into_iter().zip(contents.into_iter().chain(std::iter::repeat(Vec::new()))).collect();

    // Obfuscation: names written with #xx escapes (/J#61vaScript).
    // Only counts '#xx' inside a /Name token, not in ordinary text.
    let in_name = |k: usize| {
        let start = k.saturating_sub(40);
        raw[start..k].iter().rposition(|&c| !(c.is_ascii_alphanumeric() || c == b'#')).is_some_and(|p| raw[start + p] == b'/')
    };
    let hex_names = (1..raw.len().saturating_sub(3))
        .filter(|&k| raw[k] == b'#' && raw[k + 1].is_ascii_hexdigit() && raw[k + 2].is_ascii_hexdigit() && in_name(k))
        .count();
    if hex_names > 0 {
        out.push((Ind::PdfObfuscation, format!("hex-escaped names x{hex_names} (hides keywords from scanners)")));
    }
    for kw in [&b"/JavaScript"[..], b"/OpenAction", b"/Launch"] {
        if count_name(raw, kw) == 0 && count_name(doc, kw) > 0 {
            let k = String::from_utf8_lossy(&kw[1..]).into_owned();
            out.push((Ind::PdfObfuscation, format!("{k} only visible after decompression (hidden from naive scanners)")));
        }
    }
    Triage { indicators: out, scripts, info, annots }
}
