//! Executes the document's JavaScript against a fake Adobe Reader
//! (harness.js) to show what it *would do* in a real reader. QuickJS runs as
//! nobody under the seccomp monitor with no network, inside the VM.

use crate::monitor::{self, Net};
use crate::triage::Triage;
use airlock_proto::Ind;
use std::time::Duration;

const HARNESS: &str = include_str!("harness.js");

/// Encodes bytes as a JS string literal (bytes are taken as Latin-1, like
/// Reader does for PDFDocEncoding strings).
fn js_str(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() + 2);
    s.push('"');
    for &c in b {
        match c {
            b'"' => s.push_str("\\\""),
            b'\\' => s.push_str("\\\\"),
            0x20..=0x7e => s.push(c as char),
            _ => s.push_str(&format!("\\u{c:04x}")),
        }
    }
    s.push('"');
    s
}

pub fn run(t: &Triage, work: &str) -> Vec<(Ind, String)> {
    if t.scripts.is_empty() {
        return Vec::new();
    }
    let info: Vec<String> = t.info.iter().map(|(k, v)| format!("{}: {}", js_str(k.as_bytes()), js_str(v))).collect();
    let annots: Vec<String> = t
        .annots
        .iter()
        .map(|(s, c)| format!("{{subject: {}, contents: {}}}", js_str(s), js_str(c)))
        .collect();
    let mut prog = String::from(HARNESS);
    prog.push_str(&format!("\n__airlockSetup({{{}}}, [{}]);\n", info.join(", "), annots.join(", ")));
    // Automatic scripts run first (as in a reader); the others are run too,
    // to reveal intent, but what they do is labelled as needing a click.
    for (i, sc) in t.scripts.iter().enumerate() {
        prog.push_str(&format!("__airlockRun(\"script {}\", {});\n", i + 1, js_str(&sc.code)));
    }
    let path = format!("{work}/emulate.js");
    if std::fs::write(&path, prog).is_err() {
        return vec![(Ind::RendererAbnormal, "emulator: could not write script".into())];
    }

    let r = monitor::run(&["/usr/bin/qjs", &path], work, &monitor::Opts { mem_limit: Some(1 << 30), ..monitor::Opts::new(Net::Deny, Duration::from_secs(15)) });
    let mut out = r.events;
    let stdout = r.stdout.unwrap_or_default();
    let mut current: Option<&crate::triage::Script> = None;
    for line in String::from_utf8_lossy(&stdout).lines() {
        let Some(rest) = line.strip_prefix("@@AIRLOCK ") else { continue };
        let mut parts = rest.splitn(3, ' ');
        let (kind, cat, text) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""), parts.next().unwrap_or(""));
        if kind == "RUN" {
            current = text.strip_prefix("script ").and_then(|n| n.parse::<usize>().ok()).and_then(|n| t.scripts.get(n.wrapping_sub(1)));
            continue;
        }
        let ind = match kind {
            "CALL" => Ind::JsCall,
            "EXPLOIT" => Ind::JsExploit,
            "EVAL" => Ind::JsEval,
            "ERROR" => Ind::JsError,
            _ => continue,
        };
        let text = match current {
            Some(sc) if ind == Ind::JsCall && !sc.auto => format!("{cat}: (on user action: {}) {text}", sc.trigger),
            _ if ind == Ind::JsCall => format!("{cat}: {text}"),
            _ => text.to_string(),
        };
        if !out.iter().any(|(i, t)| *i == ind && *t == text) {
            out.push((ind, text));
        }
    }
    out
}
