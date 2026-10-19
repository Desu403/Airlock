//! E-mail messages (.eml): read inside the VM by guest/email_render.py
//! (Python's standard library), shown as a page; attachments open like an
//! archive's files (airlock.entry=N, in a VM of their own).

use crate::monitor::{self, Net, Opts};
use airlock_proto::Ind;
use std::time::Duration;

const RENDER: &str = "/usr/lib/airlock/email_render.py";
const TIMEOUT: Duration = Duration::from_secs(60);

/// An e-mail: text whose first lines are headers such as From:, To:,
/// Subject:, Date:, Received:, Message-ID: or MIME-Version: (at least two).
pub fn is_email(doc: &[u8]) -> bool {
    let head = String::from_utf8_lossy(&doc[..doc.len().min(16384)]);
    let header_block = head.split("\n\n").next().unwrap_or("").to_ascii_lowercase();
    let known = ["from:", "to:", "subject:", "date:", "received:", "message-id:", "mime-version:", "return-path:"];
    let lines: Vec<&str> = header_block.lines().collect();
    let first_ok = lines.first().is_some_and(|l| l.contains(':') && !l.starts_with(' ') && l.split(':').next().is_some_and(|k| !k.contains(' ')));
    first_ok && known.iter().filter(|k| lines.iter().any(|l| l.starts_with(*k))).count() >= 2
}

/// The page (`<work>/email.pdf`), the attachments as archive entries, and links.
pub struct Page {
    pub pdf: Option<String>,
    pub entries: Vec<crate::archive::Entry>,
    pub links: Vec<String>,
}

pub fn page(path: &str, work: &str, net: Net) -> (Vec<(Ind, String)>, Page) {
    let xhtml = format!("{work}/email.xhtml");
    let env = [("PYTHONDONTWRITEBYTECODE", "1"), ("HOME", work)];
    let r = monitor::run(&["/usr/bin/python3", "-I", RENDER, "page", path, &xhtml], work, &Opts { env: &env, ..Opts::new(net, TIMEOUT) });
    let mut events = r.events;
    let out = String::from_utf8_lossy(&r.stdout.unwrap_or_default()).into_owned();
    let mut entries = Vec::new();
    let mut links = Vec::new();
    for line in out.lines() {
        if let Some(rest) = line.strip_prefix("@@ATT ") {
            let mut f = rest.splitn(3, ' ');
            if let (Some(_), Some(size), Some(name)) = (f.next(), f.next(), f.next()) {
                entries.push(crate::archive::Entry { path: name.to_string(), size: size.parse().unwrap_or(0), encrypted: false, dir: false });
            }
        } else if let Some(u) = line.strip_prefix("@@LINK ") {
            links.push(u.to_string());
        }
    }
    let mut pdf = None;
    if std::path::Path::new(&xhtml).exists() {
        let p = format!("{work}/email.pdf");
        let r = monitor::run(&["/usr/bin/mutool", "convert", "-W", "595", "-H", "842", "-o", &p, &xhtml], work, &Opts::new(net, TIMEOUT));
        events.extend(r.events);
        if std::path::Path::new(&p).exists() {
            pdf = Some(p);
        }
    }
    (events, Page { pdf, entries, links })
}

/// Attachment `n`'s bytes, unpacked inside this VM.
pub fn extract(path: &str, n: usize, work: &str, net: Net) -> (Vec<(Ind, String)>, Option<Vec<u8>>) {
    let out = format!("{work}/email-attachment");
    let env = [("PYTHONDONTWRITEBYTECODE", "1"), ("HOME", work)];
    let r = monitor::run(&["/usr/bin/python3", "-I", RENDER, "extract", path, &n.to_string(), &out], work, &Opts { env: &env, ..Opts::new(net, TIMEOUT) });
    let bytes = std::fs::read(&out).ok().filter(|b| !b.is_empty());
    let _ = std::fs::remove_file(&out);
    (r.events, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn detect() {
        assert!(is_email(b"From: a@example.org\nTo: b@example.net\nSubject: hi\n\nbody\n"));
        assert!(is_email(b"Received: from mx\nMessage-ID: <1@x>\nFrom: a@x\n\nbody"));
        assert!(!is_email(b"# Notes\nFrom: here to there\n\ntext"));
        assert!(!is_email(b"import os\nprint('Subject: x')\n"));
    }
}
