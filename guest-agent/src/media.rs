//! Images and plain text / source code: identified by content, turned into a
//! PDF inside the VM (MuPDF for images, Pygments + MuPDF's layout for text),
//! then shown like any document. Nothing here runs the file.

use crate::monitor::{self, Net, Opts};
use airlock_proto::Ind;
use std::time::Duration;

const CONVERT_TIMEOUT: Duration = Duration::from_secs(60);
const CODE_RENDER: &str = "/usr/lib/airlock/code_render.py";

/// Image formats by their first bytes; the name is MuPDF's or ImageMagick's
/// extension for it.
pub fn image_kind(doc: &[u8]) -> Option<&'static str> {
    let at = |off: usize, magic: &[u8]| doc.len() >= off + magic.len() && &doc[off..off + magic.len()] == magic;
    if at(0, b"\x89PNG\r\n\x1a\n") {
        Some("png")
    } else if at(0, &[0xFF, 0xD8, 0xFF]) {
        Some("jpg")
    } else if at(0, b"GIF87a") || at(0, b"GIF89a") {
        Some("gif")
    } else if at(0, b"RIFF") && at(8, b"WEBP") {
        Some("webp")
    } else if at(0, b"II*\0") || at(0, b"MM\0*") {
        Some("tif")
    } else if at(0, b"BM") && doc.len() > 26 && matches!(u32::from_le_bytes([doc[14], doc[15], doc[16], doc[17]]), 12 | 40 | 52 | 56 | 108 | 124) {
        Some("bmp")
    } else if at(0, b"\0\0\0\x0cjP  ") || at(0, &[0xFF, 0x4F, 0xFF, 0x51]) {
        Some("jp2")
    } else if at(0, b"8BPS") {
        Some("psd")
    } else if at(4, b"ftypavif") || at(4, b"ftypavis") {
        Some("avif")
    } else if at(4, b"ftypheic") || at(4, b"ftypheix") || at(4, b"ftypmif1") {
        Some("heic")
    } else if at(0, &[0, 0, 1, 0]) && doc.len() > 22 && doc[4] > 0 && doc[5] == 0 {
        Some("ico")
    } else if is_svg(doc) {
        Some("svg")
    } else {
        None
    }
}

fn is_svg(doc: &[u8]) -> bool {
    let head = String::from_utf8_lossy(&doc[..doc.len().min(4096)]).to_ascii_lowercase();
    let t = head.trim_start_matches('\u{feff}').trim_start();
    (t.starts_with("<?xml") || t.starts_with("<svg") || t.starts_with("<!--") || t.starts_with("<!doctype svg")) && t.contains("<svg") && !t.contains("<html")
}

/// Text (any language, source code, logs, CSV...): no NUL bytes outside a
/// UTF-16 file, and almost no other control characters.
pub fn is_text(doc: &[u8]) -> bool {
    let sample = &doc[..doc.len().min(65536)];
    if sample.starts_with(b"\xff\xfe") || sample.starts_with(b"\xfe\xff") {
        return true;
    }
    if sample.contains(&0) {
        return false;
    }
    let control = sample.iter().filter(|&&b| b < 0x20 && !matches!(b, b'\t' | b'\n' | b'\r' | 0x0c | 0x1b)).count();
    control * 100 <= sample.len().max(1)
}

/// Converters that read the image themselves (MuPDF); the others go through
/// ImageMagick to PNG first.
fn mupdf_reads(ext: &str) -> bool {
    matches!(ext, "png" | "jpg" | "gif" | "tif" | "bmp" | "jp2" | "psd" | "svg")
}

/// Image -> `<work>/image.pdf` (one page per frame MuPDF shows).
pub fn convert_image(path: &str, ext: &str, work: &str, net: Net) -> (Vec<(Ind, String)>, Option<String>) {
    let mut events = Vec::new();
    let mut src = path.to_string();
    if !mupdf_reads(ext) {
        // First frame only ([0]); ImageMagick never delegates to other programs here.
        let png = format!("{work}/image-conv.png");
        let input = format!("{ext}:{path}[0]");
        let r = monitor::run(&["/usr/bin/magick", &input, &png], work, &Opts::new(net, CONVERT_TIMEOUT));
        events.extend(r.events);
        if !std::path::Path::new(&png).exists() {
            return (events, None);
        }
        src = png;
    }
    let pdf = format!("{work}/image.pdf");
    let r = monitor::run(&["/usr/bin/mutool", "convert", "-o", &pdf, &src], work, &Opts::new(net, CONVERT_TIMEOUT));
    events.extend(r.events);
    let ok = std::path::Path::new(&pdf).exists();
    (events, ok.then_some(pdf))
}

/// Text or code -> syntax-coloured `<work>/code.pdf`. `ext` picks the language
/// (from the host: the file's extension); without it Pygments guesses.
pub fn convert_text(path: &str, ext: Option<&str>, work: &str, net: Net) -> (Vec<(Ind, String)>, Option<String>, String) {
    let xhtml = format!("{work}/code.xhtml");
    let r = monitor::run(
        &["/usr/bin/python3", "-I", CODE_RENDER, path, &xhtml, ext.unwrap_or(""), "dark"],
        work,
        &Opts { env: &[("PYTHONDONTWRITEBYTECODE", "1"), ("HOME", work)], ..Opts::new(net, CONVERT_TIMEOUT) },
    );
    let mut events = r.events;
    let lang = String::from_utf8_lossy(&r.stdout.unwrap_or_default())
        .lines()
        .find_map(|l| l.strip_prefix("@@LANG ").map(str::to_string))
        .unwrap_or_else(|| "Text".into());
    if !std::path::Path::new(&xhtml).exists() {
        return (events, None, lang);
    }
    let pdf = format!("{work}/code.pdf");
    let r = monitor::run(&["/usr/bin/mutool", "convert", "-W", "595", "-H", "842", "-o", &pdf, &xhtml], work, &Opts::new(net, CONVERT_TIMEOUT));
    events.extend(r.events);
    let ok = std::path::Path::new(&pdf).exists();
    (events, ok.then_some(pdf), lang)
}

fn count(hay: &str, needle: &str) -> usize {
    hay.matches(needle).count()
}

/// Found tokens, for the evidence line.
fn found<'a>(hay: &str, needles: &[&'a str]) -> Vec<&'a str> {
    needles.iter().copied().filter(|n| hay.contains(n)).collect()
}

/// The longest run of base64 characters, skipping inline pictures
/// ("data:image/...;base64,"), which web pages carry legitimately.
fn longest_base64(text: &str) -> usize {
    let b = text.as_bytes();
    let (mut best, mut run, mut start) = (0, 0, 0);
    for (i, &c) in b.iter().enumerate() {
        if c.is_ascii_alphanumeric() || c == b'+' || c == b'/' || c == b'=' {
            if run == 0 {
                start = i;
            }
            run += 1;
        } else {
            let picture = text[..start].rfind("data:").is_some_and(|d| start - d < 60 && text[d..start].starts_with("data:image/"));
            if !picture {
                best = best.max(run);
            }
            run = 0;
        }
    }
    best.max(run)
}

/// Dangerous patterns in a script (Windows Script Host, PowerShell, batch,
/// HTA / HTML): conservative, so ordinary code stays clean. Never run.
pub fn script_check(doc: &[u8]) -> Vec<(Ind, String)> {
    let text = String::from_utf8_lossy(&doc[..doc.len().min(4 << 20)]);
    let l = text.to_ascii_lowercase();
    let mut out = Vec::new();
    let download = found(&l, &[
        "msxml2.xmlhttp", "msxml2.serverxmlhttp", "microsoft.xmlhttp", "winhttp.winhttprequest", "net.webclient", "downloadstring(", "downloadfile(",
        "downloaddata(", "invoke-webrequest", "invoke-restmethod", "start-bitstransfer", "bitsadmin /transfer", "certutil -urlcache", "certutil.exe -urlcache",
        "urldownloadtofile", "curl.exe ", "wget.exe ",
    ]);
    let run = found(&l, &[
        "wscript.shell", "shell.application", "shellexecute", "start-process", "invoke-expression", "iex(", "| iex", "|iex", "iex (", "createprocess",
        "win32_process", "cmd /c ", "cmd.exe /c", "mshta ", "mshta.exe", "regsvr32 /s", "rundll32 ", "rundll32.exe", "wmic process call create", ".savetofile",
    ]);
    if !download.is_empty() && !run.is_empty() {
        out.push((Ind::Script, format!("download-run: downloads with {} and runs with {}", download.join(", "), run.join(", "))));
    }
    // PowerShell told to hide: an encoded command, or a hidden window that
    // decodes and runs something.
    let encoded = ["-encodedcommand ", "-enc ", "-ec ", "-e "].iter().any(|flag| {
        l.match_indices(flag).any(|(i, _)| l[i + flag.len()..].chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=').count() >= 40)
    }) && l.contains("powershell");
    let hidden = (l.contains("-windowstyle hidden") || l.contains("-w hidden") || l.contains("-window hidden")) && (l.contains("frombase64string") || l.contains("iex") || l.contains("invoke-expression"));
    if encoded || hidden {
        out.push((Ind::Script, format!("hidden-powershell: {}", if encoded { "PowerShell with an encoded command" } else { "PowerShell in a hidden window that decodes and runs code" })));
    }
    // HTML smuggling: a page that builds a file (Blob) and downloads it.
    if l.contains("<script") && (l.contains("new blob(") || l.contains("blob([")) && (l.contains("createobjecturl") || l.contains("mssaveoropenblob") || l.contains("mssaveblob"))
        && (l.contains(".download") || l.contains("download=") || l.contains("mssaveoropenblob") || l.contains(".click()"))
    {
        out.push((Ind::Script, "smuggling: a web page that builds a file in the browser (Blob) and starts a download".into()));
    }
    let wsh = found(&l, &["wscript.shell", "shell.application", "activexobject(", "wscript.createobject", "scripting.filesystemobject", "createobject(\"wscript"]);
    if out.is_empty() && !wsh.is_empty() {
        out.push((Ind::Script, format!("shell: uses {}", wsh.join(", "))));
    }
    let chr = count(&l, "chr(") + count(&l, "chrw(");
    let fcc = count(&l, "fromcharcode");
    let b64 = longest_base64(&text);
    let obf = if chr > 80 {
        Some(format!("{chr} characters built with Chr()"))
    } else if fcc > 30 {
        Some(format!("{fcc} uses of String.fromCharCode"))
    } else if l.contains("eval(") && l.contains("unescape(") {
        Some("eval() of unescape()d text".into())
    } else if b64 >= 4000 && (l.contains("eval") || l.contains("iex") || l.contains("frombase64string") || l.contains("atob(") || l.contains("execute")) {
        Some(format!("a {b64}-character encoded blob that the script decodes and runs"))
    } else {
        None
    };
    if let Some(o) = obf {
        out.push((Ind::Script, format!("obfuscated: {o}")));
    }
    out
}

/// Where the image data ends, for formats with a clear end marker.
fn image_end(doc: &[u8], ext: &str) -> Option<usize> {
    match ext {
        "png" => doc.windows(8).rposition(|w| &w[4..] == b"IEND").map(|i| i + 12),
        "jpg" => doc.windows(2).rposition(|w| w == [0xFF, 0xD9]).map(|i| i + 2),
        _ => None,
    }
}

/// Data after the end of the picture: a ZIP, program or web page glued on
/// (the image is also that file: a polyglot), or simply bytes no viewer shows.
pub fn hidden_data(doc: &[u8], ext: &str) -> Vec<(Ind, String)> {
    let Some(end) = image_end(doc, ext) else { return Vec::new() };
    let tail = &doc[end.min(doc.len())..];
    let start = tail.iter().position(|b| !b" \t\r\n\x00".contains(b)).unwrap_or(tail.len());
    let tail = &tail[start..];
    let name = ext.to_ascii_uppercase();
    if tail.windows(4).any(|w| w == b"PK\x05\x06" || w == b"PK\x01\x02") {
        return vec![(Ind::HiddenData, format!("{} bytes after the end of the {name} picture, containing a ZIP archive's index: the file is also a ZIP archive (a polyglot)", tail.len()))];
    }
    let lower = tail[..tail.len().min(4096)].to_ascii_lowercase();
    if tail.len() > 64 && (lower.windows(5).any(|w| w == b"<html") || lower.windows(7).any(|w| w == b"<script")) {
        return vec![(Ind::HiddenData, format!("{} bytes after the end of the {name} picture, containing a web page with scripts (a polyglot)", tail.len()))];
    }
    if tail.len() > 1024 {
        let kind = (0..tail.len().min(4096)).find_map(|i| crate::triage::payload_kind(&tail[i..]));
        return vec![(
            Ind::HiddenData,
            match kind {
                Some(k) => format!("{} bytes after the end of the {name} picture, containing a {k} (a polyglot)", tail.len()),
                None => format!("{} bytes after the end of the {name} picture that no viewer shows", tail.len()),
            },
        )];
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn kinds() {
        assert_eq!(image_kind(b"\x89PNG\r\n\x1a\n...."), Some("png"));
        assert_eq!(image_kind(&[0xFF, 0xD8, 0xFF, 0xE0, 0, 0]), Some("jpg"));
        assert_eq!(image_kind(b"RIFF\0\0\0\0WEBPVP8 "), Some("webp"));
        assert_eq!(image_kind(b"<?xml version=\"1.0\"?>\n<svg xmlns=\"http://www.w3.org/2000/svg\"/>"), Some("svg"));
        assert_eq!(image_kind(b"<html><svg/></html>"), None);
        assert!(is_text(b"#include <stdio.h>\nint main() { return 0; }\n"));
        assert!(is_text("caf\u{e9} \u{1F600}\n".as_bytes()));
        assert!(!is_text(b"MZ\x90\0\x03\0\0\0"));
        assert!(!is_text(&[1, 2, 3, 4, 5, 6, 7, 8, 14, 15, 16]));
    }
    #[test]
    fn scripts() {
        let k = |s: &str| script_check(s.as_bytes()).iter().map(|(_, t)| t.split(':').next().unwrap().to_string()).collect::<Vec<_>>();
        assert_eq!(k("Set x = CreateObject(\"MSXML2.XMLHTTP\")\nx.Open \"GET\", u\nSet s = CreateObject(\"WScript.Shell\")\ns.Run \"a.exe\""), ["download-run"]);
        assert_eq!(k("powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBi"), ["hidden-powershell"]);
        assert_eq!(k("<script>var b=new Blob([d]);var a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='x.iso';a.click()</script>"), ["smuggling"]);
        assert_eq!(k("var sh = new ActiveXObject(\"WScript.Shell\");"), ["shell"]);
        assert!(k("#include <stdio.h>\nint main(void) { puts(\"hi\"); return 0; }\n").is_empty());
        assert!(k("import requests\nr = requests.get(url)\nprint(r.text)\n").is_empty());
        assert!(k("<img src=\"data:image/png;base64,iVBORw0KGgo").is_empty());
        assert!(k("#!/bin/sh\ncurl -fsSL https://example.org/x.tar.gz | tar xz\n").is_empty());
    }
    #[test]
    fn polyglot() {
        let mut png = b"\x89PNG\r\n\x1a\n\0\0\0\0IEND\xaeB`\x82".to_vec();
        assert!(hidden_data(&png, "png").is_empty());
        png.extend_from_slice(b"PK\x03\x04 ... PK\x05\x06");
        assert_eq!(hidden_data(&png, "png").len(), 1);
    }
}
