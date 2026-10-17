//! Known-malware signatures: YARA (rules from YARA-Forge, compiled into the
//! image) over the document *and* its unpacked insides — the decompressed
//! PDF, and for Office files every ZIP part, OLE stream and macro's source
//! (guest/unpack.py). yara runs as nobody under the monitor, without network,
//! like every other program that reads the document.

use crate::monitor::{self, Net, Opts};
use airlock_proto::Ind;
use std::collections::HashMap;
use std::time::Duration;

const RULES: &str = "/usr/lib/airlock/rules.yarc";
const META: &str = "/usr/lib/airlock/yara-meta.tsv";
const UNPACK: &str = "/usr/lib/airlock/unpack.py";
const MAX_MATCHES: usize = 30;
/// tmpfs, writable by the unpacker (see main.rs).
pub const SCRATCH: &str = "/run/scan";

/// Rule name -> (score, description, author).
fn meta() -> HashMap<String, (u32, String, String)> {
    let text = std::fs::read_to_string(META).unwrap_or_default();
    text.lines()
        .filter_map(|l| {
            let mut f = l.split('\t');
            let (name, score) = (f.next()?, f.next()?.parse().ok()?);
            Some((name.to_string(), (score, f.next().unwrap_or("").to_string(), f.next().unwrap_or("").to_string())))
        })
        .collect()
}

fn generic(rule: &str) -> bool {
    rule.to_ascii_uppercase().split('_').any(|w| matches!(w, "SUSP" | "INDICATOR" | "GEN" | "GENERIC" | "ANOMALY" | "HUNTING" | "INFO"))
}

fn ident(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// `doc`: the document as written to the work dir; `clean`: the
/// decompressed PDF from triage, if any; `office`: unpack its insides first.
pub fn scan(work: &str, doc: &str, clean: Option<&str>, office: bool) -> Vec<(Ind, String)> {
    if !std::path::Path::new(RULES).exists() {
        return Vec::new();
    }
    let mut events = Vec::new();
    // Files to scan, and what to call each in the report.
    let mut targets: Vec<(String, String)> = vec![(doc.to_string(), "the file itself".into())];
    if let Some(c) = clean.filter(|c| std::path::Path::new(c).exists()) {
        targets.push((c.to_string(), "decompressed PDF".into()));
    }
    if office {
        let parts = format!("{SCRATCH}/parts");
        let r = monitor::run(
            &["/usr/bin/python3", "-I", UNPACK, doc, &parts],
            work,
            &Opts { env: &[("PYTHONDONTWRITEBYTECODE", "1"), ("HOME", work)], ..Opts::new(Net::Deny, Duration::from_secs(90)) },
        );
        events.extend(r.events);
        let index = std::fs::read_to_string(format!("{parts}/index.tsv")).unwrap_or_default();
        for line in index.lines().take(2000) {
            let Some((name, what)) = line.split_once('\t') else { continue };
            if name.len() == 4 && name.bytes().all(|b| b.is_ascii_digit()) {
                targets.push((format!("{parts}/{name}"), what.to_string()));
            }
        }
    }
    events.extend(matches(&targets, work));
    events
}

/// Runs the rules over `targets` ((path, what to call it)) and reports
/// each rule that matched, with where.
pub fn matches(targets: &[(String, String)], cwd: &str) -> Vec<(Ind, String)> {
    if targets.is_empty() || !std::path::Path::new(RULES).exists() {
        return Vec::new();
    }
    let mut events = Vec::new();
    let list = format!("{SCRATCH}/targets");
    let body: String = targets.iter().map(|(p, _)| format!("{p}\n")).collect();
    if std::fs::write(&list, body).is_err() {
        return events;
    }
    let r = monitor::run(
        &["/usr/bin/yara", "-w", "-N", "-a", "60", "-p", "2", "--scan-list", "-C", RULES, &list],
        cwd,
        &Opts { mem_limit: Some(2048 << 20), ..Opts::new(Net::Deny, Duration::from_secs(120)) },
    );
    events.extend(r.events);
    let out = String::from_utf8_lossy(&r.stdout.unwrap_or_default()).into_owned();
    let label: HashMap<&str, &str> = targets.iter().map(|(p, w)| (p.as_str(), w.as_str())).collect();
    // Rule -> where it matched, in the order yara reported.
    let mut hits: Vec<(String, Vec<String>)> = Vec::new();
    for line in out.lines().take(5000) {
        let Some((rule, path)) = line.split_once(' ') else { continue };
        if !ident(rule) {
            continue;
        }
        let at = label.get(path).copied().unwrap_or("an unpacked part").to_string();
        match hits.iter_mut().find(|(r, _)| r == rule) {
            Some((_, w)) => w.push(at),
            None => hits.push((rule.to_string(), vec![at])),
        }
    }
    let meta = meta();
    let mut found: Vec<(u32, String, String)> = hits
        .into_iter()
        .map(|(rule, wh)| {
            let (score, desc, _author) = meta.get(&rule).cloned().unwrap_or((50, String::new(), String::new()));
            // "Detects ... [in part word/_rels/document.xml.rels] (rule RULE_NAME)"
            let mut t = if desc.is_empty() { rule.clone() } else { desc };
            t += &format!(" [in {}", wh[0]);
            if wh.len() > 1 {
                t += &format!(" +{} more", wh.len() - 1);
            }
            t += &format!("] (rule {rule})");
            (score, rule, t)
        })
        .collect();
    found.sort_by(|a, b| b.0.cmp(&a.0));
    for (score, rule, text) in found.into_iter().take(MAX_MATCHES) {
        let ind = match score {
            // Rules for a technique, not a family or exploit ("INDICATOR_OLE_
            // Remotetemplate", "SUSP_..."): the static triage already rates
            // the technique, so they never decide the verdict on their own.
            _ if generic(&rule) => if score >= 60 { Ind::YaraMedium } else { Ind::YaraLow },
            75.. => Ind::YaraHigh,
            60..=74 => Ind::YaraMedium,
            _ => Ind::YaraLow,
        };
        events.push((ind, text));
    }
    events
}
