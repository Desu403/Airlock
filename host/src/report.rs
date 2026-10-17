//! Turns raw signals into a verdict a human can act on. The *host* decides
//! what each signal means; guests only ever supply a code and short text.

use airlock_proto::Ind;
use std::path::Path;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Source {
    /// Seen from outside the VM — the document cannot fake or hide these.
    Outside,
    /// Seen by the in-VM monitor — reliable unless the guest kernel fell.
    Monitor,
    /// Static structure of the file.
    Static,
    /// What the document's JavaScript did in the fake reader.
    Emulated,
    /// YARA rules for known malware matched its bytes or unpacked insides.
    Signature,
}

pub struct Finding {
    pub source: Source,
    pub severity: Severity,
    pub attack: &'static str,
    pub what: String,
}

fn guest_finding(ind: Ind, text: &str) -> Finding {
    use Severity::*;
    let (source, severity, attack, what) = match ind {
        Ind::PdfFeature => {
            let t = text.to_ascii_lowercase();
            let (sev, att) = if t.starts_with("javascript") {
                (Medium, "T1059.007 JavaScript")
            } else if t.contains("launch") {
                (High, "T1204.002 Malicious File")
            } else if t.contains("on open") || t.contains("automatic") {
                (Medium, "T1204.002 Malicious File")
            } else if t.contains("embedded") {
                (Medium, "T1027.009 Embedded Payloads")
            } else if t.contains("flash") || t.contains("xfa") {
                (Medium, "T1203 Exploitation for Client Execution")
            } else {
                (Low, "-")
            };
            (Source::Static, sev, att, format!("contains {text}"))
        }
        Ind::PdfUri if text.starts_with("mailto:") => (Source::Static, Info, "-", format!("email link {text}")),
        Ind::PdfUri => (Source::Static, Info, "T1566.002 Spearphishing Link", format!("link to {text}")),
        Ind::PdfJs => (Source::Static, Medium, "T1059.007 JavaScript", format!("JavaScript: {text}")),
        // Compressed object streams are how modern PDF writers save files.
        Ind::PdfObfuscation if text.contains("only visible after decompression") => {
            (Source::Static, Low, "T1027 Obfuscated Files", format!("{text} (normal in modern PDFs; also hides it from naive scanners)"))
        }
        Ind::PdfObfuscation => (Source::Static, Medium, "T1027 Obfuscated Files", text.to_string()),
        Ind::JsCall => {
            let (cat, rest) = text.split_once(": ").unwrap_or(("other", text));
            let (mut sev, att, mut verb) = match cat {
                "net" => (High, "T1071.001 Web Protocols", "contacts the internet:"),
                "launch" => (High, "T1204.002 Malicious File", "opens/launches:"),
                "drop" => (High, "T1105 Ingress Tool Transfer", "writes a file:"),
                "persist" => (Medium, "T1546 Event Triggered Execution", "installs a hook:"),
                "priv" => (Medium, "T1068 Exploitation for Privilege Escalation", "privileged call:"),
                "timer" => (Low, "-", "schedules code:"),
                "ui" => (Info, "-", "shows UI:"),
                _ => (Info, "-", "calls"),
            };
            // Only if the reader clicks/types (a button, a form field): opening
            // a website then is what a hyperlink does; running or dropping
            // something still deserves attention.
            if rest.starts_with("(on user action") {
                sev = match cat {
                    "net" => Low,
                    "launch" | "drop" => Medium,
                    _ => sev.min(Low),
                };
                verb = match cat {
                    "net" => "would open a website if clicked:",
                    "launch" => "would open/launch if clicked:",
                    "drop" => "would write a file if clicked:",
                    _ => verb,
                };
            }
            (Source::Emulated, sev, att, format!("{verb} {rest}"))
        }
        Ind::JsExploit => (Source::Emulated, High, "T1203 Exploitation for Client Execution", format!("EXPLOIT: {text}")),
        Ind::JsEval => (Source::Emulated, Low, "T1027 Obfuscated Files", format!("unpacked layer: {text}")),
        Ind::JsError => (Source::Emulated, Info, "-", format!("script error: {text}")),
        Ind::OfficeMacro => (Source::Static, Medium, "T1059.005 Visual Basic", format!("VBA macro {text}")),
        Ind::OfficeAutoExec => (Source::Static, High, "T1204.002 Malicious File", format!("macro runs automatically on open: {text}")),
        Ind::OfficeSuspicious => {
            let k = text.to_ascii_lowercase();
            let dangerous = [
                "shell", "urldownloadtofile", "powershell", "createprocess", "run", "exec", "wscript", "mshta", "certutil", "regsvr32", "rundll32",
                // script-host execution (see EXEC_PRIMITIVES in guest/office_triage.py)
                "scriptcontrol", "addcode", "callbyname", "macscript",
            ]
                .iter()
                .any(|d| k.split(':').next().unwrap_or("").contains(d));
            (Source::Static, if dangerous { High } else { Medium }, "T1059.005 Visual Basic", format!("macro uses {text}"))
        }
        Ind::OfficeIoc => (Source::Static, Medium, "T1105 Ingress Tool Transfer", format!("macro mentions {text}")),
        Ind::OfficeObfuscation => (Source::Static, Medium, "T1027 Obfuscated Files", format!("macro hides strings: {text}")),
        Ind::OfficeStomping => (Source::Static, High, "T1564.007 VBA Stomping", text.to_string()),
        Ind::OfficeXlm => (Source::Static, High, "T1059 Command and Scripting Interpreter", text.to_string()),
        Ind::OfficeExternal => {
            let (sev, att) = if text.starts_with("remote template") {
                (High, "T1221 Template Injection")
            } else if text.starts_with("external image") {
                (Medium, "T1187 Forced Authentication")
            } else {
                (Medium, "T1221 Template Injection")
            };
            (Source::Static, sev, att, text.to_string())
        }
        Ind::OfficeExploit => (Source::Static, High, "T1203 Exploitation for Client Execution", format!("EXPLOIT: {text}")),
        Ind::OfficeEmbedded => (Source::Static, Medium, "T1027.009 Embedded Payloads", text.to_string()),
        Ind::OfficeLink => (Source::Static, Info, "T1566.002 Spearphishing Link", format!("link to {text}")),
        Ind::OfficeContainer => (Source::Static, Low, "-", text.to_string()),
        Ind::OfficeError => (Source::Static, Info, "-", format!("triage: {text}")),
        Ind::YaraHigh | Ind::YaraMedium | Ind::YaraLow => {
            let sev = match ind {
                Ind::YaraHigh => High,
                Ind::YaraMedium => Medium,
                _ => Low,
            };
            (Source::Signature, sev, "-", text.to_string())
        }
        Ind::Exec => (Source::Monitor, High, "T1059 Command and Scripting Interpreter", format!("tried to run {text} (blocked)")),
        Ind::ProcessCreate => (Source::Monitor, High, "T1203 Exploitation for Client Execution", format!("tried to start a process: {text} (blocked)")),
        Ind::Socket => (Source::Monitor, Medium, "T1071 Application Layer Protocol", format!("opened a network socket ({text})")),
        Ind::Connect => (Source::Monitor, High, "T1071 Application Layer Protocol", format!("network: {text}")),
        Ind::KernelSurface => (Source::Monitor, High, "T1068 Exploitation for Privilege Escalation", format!("kernel attack-surface call {text} (blocked)")),
        Ind::Ptrace => (Source::Monitor, High, "T1055 Process Injection", format!("{text} (blocked)")),
        Ind::RendererAbnormal => (Source::Monitor, Medium, "T1203 Exploitation for Client Execution", text.to_string()),
        Ind::FileDropped => {
            let exe = ["[Linux executable", "[Windows executable", "[script]", "executable-bit", "SETUID"].iter().any(|k| text.contains(k));
            (Source::Outside, if exe { High } else { Medium }, "T1105 Ingress Tool Transfer", format!("left on disk: {text}"))
        }
    };
    Finding { source, severity, attack, what }
}

fn s(v: &serde_json::Value, k: &str) -> String {
    // The sinkhole already squashes strings; re-check, it parsed hostile input.
    let raw = v.get(k).and_then(|x| x.as_str()).unwrap_or("");
    raw.chars().take(200).map(|c| if (' '..='~').contains(&c) { c } else { '?' }).collect()
}

fn sinkhole_findings(path: &Path) -> Vec<Finding> {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let mut out = Vec::new();
    for line in text.lines().take(2000) {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else { continue };
        let f = |severity, attack, what| Finding { source: Source::Outside, severity, attack, what };
        match v.get("t").and_then(|t| t.as_str()) {
            Some("dns") => out.push(f(Severity::High, "T1071.004 DNS", format!("DNS lookup of {}", s(&v, "name")))),
            Some("tcp") => {
                let dst = s(&v, "dst");
                let ev = match v.get("proto").and_then(|p| p.as_str()) {
                    Some("http") => f(Severity::High, "T1105 Ingress Tool Transfer", format!("HTTP \"{}\" Host: {} (to {dst})", s(&v, "request"), s(&v, "host"))),
                    Some("tls") => f(Severity::High, "T1573 Encrypted Channel", format!("TLS connection to {} ({dst})", s(&v, "sni"))),
                    _ => f(Severity::High, "T1095 Non-Application Layer Protocol", format!("TCP connection to {dst} sent \"{}\"", s(&v, "first_bytes"))),
                };
                out.push(ev);
            }
            Some("flow") => {
                let flow = s(&v, "flow");
                // TCP and DNS are reported richer above.
                if !flow.starts_with("tcp ") && !flow.ends_with(":53") {
                    out.push(f(Severity::High, "T1095 Non-Application Layer Protocol", format!("packets: {flow}")));
                }
            }
            _ => {}
        }
    }
    out
}

pub struct Report {
    pub findings: Vec<Finding>,
}

impl Report {
    /// `abnormal`: outside observations about the VM itself (protocol
    /// violation, unexpected death).
    pub fn build(indicators: &[(Ind, String)], sinkhole: Option<&Path>, abnormal: &[String]) -> Self {
        let mut findings: Vec<Finding> = indicators.iter().map(|(i, t)| guest_finding(*i, t)).collect();
        if let Some(p) = sinkhole {
            findings.extend(sinkhole_findings(p));
        }
        for what in abnormal {
            findings.push(Finding {
                source: Source::Outside,
                severity: Severity::High,
                attack: "T1203 Exploitation for Client Execution",
                what: what.clone(),
            });
        }
        let mut seen = std::collections::HashSet::new();
        findings.retain(|f| seen.insert(f.what.clone()));
        findings.sort_by(|a, b| b.severity.cmp(&a.severity));
        Report { findings }
    }

    pub fn verdict(&self) -> (&'static str, &'static str) {
        let behaviour = |sev| self.findings.iter().any(|f| !matches!(f.source, Source::Static | Source::Signature) && f.severity >= sev);
        // Emulated = what it *would* do in a real reader: that is behaviour.
        let static_sev = self.findings.iter().filter(|f| matches!(f.source, Source::Static | Source::Signature)).map(|f| f.severity).max();
        let has = |att: &str| self.findings.iter().any(|f| f.source == Source::Static && f.severity == Severity::High && f.attack.starts_with(att));
        // Decisive static evidence: we never run macros, so these stand on their own.
        let decisive = has("T1203") || has("T1564.007") || has("T1221") || (has("T1204.002") && has("T1059"))
            // A rule written for a known malware family or exploit.
            || self.findings.iter().any(|f| f.source == Source::Signature && f.severity == Severity::High);
        if behaviour(Severity::High) {
            ("MALICIOUS BEHAVIOUR", "the document actively tried things a document should never do")
        } else if decisive {
            ("LIKELY MALICIOUS", "contains an auto-running payload, a known exploit technique or known malware (not executed here)")
        } else if behaviour(Severity::Medium) || static_sev >= Some(Severity::Medium) {
            ("SUSPICIOUS", "risky features or odd behaviour, but no clear attack observed")
        } else {
            ("NO ACTIVE BEHAVIOUR OBSERVED", "nothing suspicious seen — this is not a guarantee of safety")
        }
    }

    pub fn print(&self) {
        let (v, why) = self.verdict();
        eprintln!("\n=== airlock report: {v} ===\n    {why}");
        for (src, title) in [
            (Source::Outside, "Seen from OUTSIDE the VM (cannot be faked by the document)"),
            (Source::Monitor, "Seen by the in-VM monitor"),
            (Source::Emulated, "What its JavaScript does in a (fake) Adobe Reader"),
            (Source::Signature, "Matches known malware (YARA rules)"),
            (Source::Static, "Static structure of the file"),
        ] {
            let items: Vec<_> = self.findings.iter().filter(|f| f.source == src).collect();
            if items.is_empty() {
                continue;
            }
            eprintln!("\n  {title}:");
            for f in items {
                let tag = match f.severity {
                    Severity::High => "HIGH",
                    Severity::Medium => "MED ",
                    Severity::Low => "LOW ",
                    Severity::Info => "info",
                };
                eprintln!("   [{tag}] {}", f.what);
                if f.attack != "-" {
                    eprintln!("          ATT&CK {}", f.attack);
                }
            }
        }
        if self.findings.is_empty() {
            eprintln!("\n  (no findings)");
        }
        eprintln!();
    }

    pub fn to_json(&self) -> serde_json::Value {
        let (v, why) = self.verdict();
        serde_json::json!({
            "verdict": v,
            "summary": why,
            "findings": self.findings.iter().map(|f| serde_json::json!({
                "source": format!("{:?}", f.source).to_lowercase(),
                "severity": format!("{:?}", f.severity).to_lowercase(),
                "attack": f.attack,
                "what": f.what,
            })).collect::<Vec<_>>()
        })
    }
}
