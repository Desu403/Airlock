//! Office documents: identify by content, triage statically with oletools,
//! convert to PDF with LibreOffice. Everything runs as nobody under the
//! monitor. Macros are never executed (headless LibreOffice does not run them).

use crate::monitor::{self, Net, Opts};
use airlock_proto::Ind;
use std::time::Duration;

const SOFFICE: &str = "/usr/lib/libreoffice/program/soffice.bin";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Pdf,
    /// Office document; the extension LibreOffice should see.
    Office(&'static str),
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

/// Content sniffing only — the file name is attacker-controlled and ignored.
pub fn detect(doc: &[u8]) -> Option<Kind> {
    let head = &doc[..doc.len().min(1024)];
    if contains(head, b"%PDF-") {
        return Some(Kind::Pdf);
    }
    if doc.starts_with(b"{\\rt") {
        return Some(Kind::Office("rtf"));
    }
    if doc.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]) {
        // OLE2: the directory stream names tell Word/Excel/PowerPoint apart.
        return Some(if contains(doc, &utf16("WordDocument")) {
            Kind::Office("doc")
        } else if contains(doc, &utf16("Workbook")) || contains(doc, &utf16("Book")) {
            Kind::Office("xls")
        } else if contains(doc, &utf16("PowerPoint Document")) {
            Kind::Office("ppt")
        } else if contains(doc, &utf16("_VBA_PROJECT")) || contains(doc, &utf16("PROJECT")) {
            // A bare macro project (PowerPoint .ppa add-ins are delivered
            // like this): nothing to show, but everything to check.
            Kind::Office("doc")
        } else {
            return None;
        });
    }
    if doc.starts_with(b"PK\x03\x04") {
        // ZIP: part names live (uncompressed) in local headers and the central directory.
        if contains(doc, b"word/") {
            return Some(Kind::Office("docx"));
        }
        if contains(doc, b"xl/") {
            return Some(Kind::Office("xlsx"));
        }
        if contains(doc, b"ppt/") {
            return Some(Kind::Office("pptx"));
        }
        if contains(&doc[..doc.len().min(256)], b"mimetypeapplication/vnd.oasis.opendocument.spreadsheet") {
            return Some(Kind::Office("ods"));
        }
        if contains(&doc[..doc.len().min(256)], b"mimetypeapplication/vnd.oasis.opendocument") {
            return Some(Kind::Office("odt"));
        }
    }
    None
}

pub fn triage(path: &str, work: &str) -> Vec<(Ind, String)> {
    let r = monitor::run(
        &["/usr/bin/python3", "-I", "/usr/lib/airlock/office_triage.py", path],
        work,
        &Opts { env: &[("PYTHONDONTWRITEBYTECODE", "1"), ("HOME", work)], ..Opts::new(Net::Deny, Duration::from_secs(90)) },
    );
    let mut out = r.events;
    for line in String::from_utf8_lossy(&r.stdout.unwrap_or_default()).lines() {
        let Some(rest) = line.strip_prefix("@@AIRLOCK ") else { continue };
        let (kind, text) = rest.split_once(' ').unwrap_or((rest, ""));
        let ind = match kind {
            "MACRO" => Ind::OfficeMacro,
            "AUTOEXEC" => Ind::OfficeAutoExec,
            "SUSPICIOUS" => Ind::OfficeSuspicious,
            "IOC" => Ind::OfficeIoc,
            "OBFUSCATION" => Ind::OfficeObfuscation,
            "STOMPING" => Ind::OfficeStomping,
            "XLM" => Ind::OfficeXlm,
            "EXTERNAL" => Ind::OfficeExternal,
            "EXPLOIT" => Ind::OfficeExploit,
            "EMBEDDED" => Ind::OfficeEmbedded,
            "LINK" => Ind::OfficeLink,
            "MALFORMED" => Ind::HiddenData,
            "CONTAINER" => Ind::OfficeContainer,
            "ERROR" => Ind::OfficeError,
            _ => continue,
        };
        if !out.iter().any(|(i, t)| *i == ind && t == text) {
            out.push((ind, text.to_string()));
        }
    }
    out
}

pub const PROFILE_TEMPLATE: &str = "/usr/lib/airlock/lo-profile-template";

/// Copies the prebuilt profile into the work dir, owned by the renderer user.
fn copy_tree(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::lchown;
    std::fs::create_dir_all(dst)?;
    lchown(dst, Some(monitor::RENDER_UID), Some(monitor::RENDER_GID))?;
    for e in std::fs::read_dir(src)? {
        let e = e?;
        let to = dst.join(e.file_name());
        if e.file_type()?.is_dir() {
            copy_tree(&e.path(), &to)?;
        } else if e.file_type()?.is_file() {
            std::fs::copy(e.path(), &to)?;
            lchown(&to, Some(monitor::RENDER_UID), Some(monitor::RENDER_GID))?;
        }
    }
    Ok(())
}

/// Converts to `<work>/office.pdf`. Returns monitor events; the caller checks
/// whether the PDF appeared.
pub fn convert(path: &str, work: &str, net: Net, ext: &str) -> Vec<(Ind, String)> {
    let dir = format!("{work}/lo-profile");
    if let Err(e) = copy_tree(std::path::Path::new(PROFILE_TEMPLATE), std::path::Path::new(&dir)) {
        return vec![(Ind::RendererAbnormal, format!("could not prepare LibreOffice profile: {e}"))];
    }
    let cache = format!("{dir}/cache");
    let profile = format!("-env:UserInstallation=file://{dir}");
    // Spreadsheets go through the profile's own macro (lo-sheets.xba): every
    // sheet fitted to the page width, so columns are not cut onto other pages.
    let single = std::fs::read_to_string("/proc/cmdline").unwrap_or_default().split_whitespace().any(|t| t == "airlock.sheets=single");
    let layout = if single { "single" } else { "pages" };
    let sheets = format!("macro:///Standard.Module1.SheetsToPdf(\"{path}\",\"{work}/office.pdf\",\"{layout}\")");
    let how: &[&str] = if matches!(ext, "xls" | "xlsx" | "ods") { &[&sheets] } else { &["--convert-to", "pdf", "--outdir", work, path] };
    let argv: Vec<&str> = [SOFFICE, &profile, "--headless", "--invisible", "--nologo", "--norestore", "--nolockcheck", "--nodefault"].iter().chain(how).copied().collect();
    let r = monitor::run(
        &argv,
        work,
        &Opts {
            mem_limit: None,
            allow_unix: true,
            allow_fork: true,
            // LibreOffice start-up probes (paper size, GnuPG). Denied, but normal.
            // Media in slides: GStreamer's plugin scanner and GLib's network
            // monitor (netlink). Denied, but normal.
            quiet_exec: &[
                "/bin/sh [sh -c paperconf 2>/dev/null]",
                "/usr/bin/gpgconf [/usr/bin/gpgconf --*",
                "/usr/lib/../libexec/gstreamer-1.0/gst-plugin-scanner [*",
                "/usr/libexec/gstreamer-1.0/gst-plugin-scanner [*",
            ],
            quiet_netlink: true,
            env: &[("HOME", &dir), ("XDG_CACHE_HOME", &cache), ("XDG_CONFIG_HOME", &dir), ("SAL_USE_VCLPLUGIN", "svp"), ("LANG", "C.UTF-8")],
            ..Opts::new(net, Duration::from_secs(120))
        },
    );
    r.events
}
