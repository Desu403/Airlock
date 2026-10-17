//! Turns raw signals into a verdict a human can act on. The *host* decides
//! what each signal means; guests only ever supply a code and short text.
//!
//! Every finding has two layers: a plain-language `title` and `explain`
//! for anyone, and the technical `what` + ATT&CK technique for experts.

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

impl Source {
    pub fn describe(self) -> &'static str {
        match self {
            Source::Outside => "Seen from outside the VM (cannot be faked by the document)",
            Source::Monitor => "Seen by the in-VM monitor",
            Source::Emulated => "What its JavaScript does in a (fake) Adobe Reader",
            Source::Signature => "Matches known malware (YARA rules)",
            Source::Static => "Static structure of the file",
        }
    }
}

pub struct Finding {
    pub source: Source,
    pub severity: Severity,
    pub attack: &'static str,
    /// Plain language, a few words: "Starts a program when opened".
    pub title: String,
    /// Plain language: why it matters, one or two sentences.
    pub explain: &'static str,
    /// Technical detail (the evidence).
    pub what: String,
}

fn finding(source: Source, severity: Severity, attack: &'static str, title: impl Into<String>, explain: &'static str, what: String) -> Finding {
    Finding { source, severity, attack, title: title.into(), explain, what }
}

const WHY_MACRO: &str = "Macros are small programs inside Office files. Most attacks through Office documents use them. airlock reads macros but never runs them.";
const WHY_EXPLOIT: &str = "This targets a known security hole in document software. On a computer without the fix, it can take over the computer as soon as the file is opened.";
const WHY_BLOCKED: &str = "Documents never need this. It was blocked inside the throwaway VM and nothing reached your computer.";

/// PDF action type -> (title, why, severity, ATT&CK), for actions that run by themselves.
fn pdf_auto_action(kind: &str) -> (&'static str, &'static str, Severity, &'static str) {
    use Severity::*;
    match kind {
        "Launch" => ("Starts a program when opened", "The PDF tells the reader to run a program or command. Real documents almost never do this; it is a classic way to infect a computer.", High, "T1204.002 Malicious File"),
        "URI" => ("Opens a website by itself", "As soon as it is opened, the document sends the reader to a web address: used to track who opened it or to lead to a phishing or malware page.", Medium, "T1204.001 Malicious Link"),
        "SubmitForm" => ("Sends data somewhere by itself", "The document submits form data to an address without you pressing anything: it can report that you opened it, or leak what is in the form.", Medium, "T1020 Automated Exfiltration"),
        "ImportData" => ("Loads data from another file by itself", "The document pulls in data from an outside file when opened.", Medium, "T1105 Ingress Tool Transfer"),
        "GoToR" | "GoToE" => ("Opens another document by itself", "Opening this file makes the reader open a second document, which can carry the actual attack.", Medium, "T1204.002 Malicious File"),
        "Rendition" | "Movie" | "Sound" | "RichMediaExecute" => ("Plays media by itself", "Embedded media players have been a common target of PDF exploits.", Medium, "T1203 Exploitation for Client Execution"),
        "Named" => ("Runs a reader command by itself", "The document triggers a reader menu command (such as Print) when opened. Unusual, rarely harmful.", Low, "-"),
        _ => ("Runs an automatic action", "The document performs an action without you doing anything.", Low, "-"),
    }
}

/// "Launch: <target> [<trigger>]": does the target run something, or open a document?
fn launches_program(text: &str) -> bool {
    let target = text.split_once(": ").map_or("", |(_, t)| t);
    let target = target.rsplit_once(" [").map_or(target, |(t, _)| t).trim().to_ascii_lowercase();
    let first = target.split_whitespace().next().unwrap_or("");
    let ext = first.rsplit_once('.').map_or("", |(_, e)| e);
    let document = ["pdf", "txt", "rtf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "odp", "htm", "html", "jpg", "jpeg", "png", "gif", "tif", "tiff", "csv", "xml", "mp3", "mp4", "avi", "wav"];
    // The first word decides: "cmd.exe /c ..." runs, "manual.pdf" opens.
    target.is_empty() || !document.contains(&ext)
}

fn guest_finding(ind: Ind, text: &str) -> Finding {
    use Severity::*;
    use Source::*;
    match ind {
        // ---- PDF structure
        Ind::PdfAutoAction => {
            let kind = text.split(':').next().unwrap_or("");
            let (title, why, sev, att) = if kind == "Launch" && !launches_program(text) {
                ("Opens another file by itself", "The document makes the reader open a different file on this computer. It does not start a program, but it is unusual.", Medium, "T1204.002 Malicious File")
            } else {
                pdf_auto_action(kind)
            };
            finding(Static, sev, att, title, why, format!("automatic action {text}"))
        }
        Ind::PdfClickAction => {
            let kind = text.split(':').next().unwrap_or("");
            let (title, why, sev, att) = match kind {
                "Launch" if !launches_program(text) => ("A link opens a file on this computer", "Clicking it opens another file (not a program).", Low, "-"),
                "Launch" => ("Would start a program if you click", "A link or button in the document is set up to run a program. Legitimate documents almost never need this.", Medium, "T1204.002 Malicious File"),
                "SubmitForm" => ("A button sends form data", "Normal for online forms; check where it sends the data before using it.", Low, "-"),
                "GoToR" | "GoToE" => ("A link opens another file", "Clicking it opens a different document.", Low, "-"),
                _ => ("A link or button runs an action", "Something happens when you click it; nothing runs by itself.", Low, "-"),
            };
            finding(Static, sev, att, title, why, format!("on click: {text}"))
        }
        Ind::PdfAttachment => {
            let t = text.to_ascii_lowercase();
            let (title, why, sev) = if t.contains("program") || t.contains("script") {
                ("Contains a hidden program or script", "A program inside a PDF has no business being there; opening the attachment would run it.", High)
            } else if t.contains("office document") || t.contains("zip archive") || t.contains("rtf document") {
                ("Contains an attached Office file or archive", "Attached Office files and archives can carry their own macros or programs. They are not checked separately here.", Medium)
            } else {
                ("Contains an attached file", "Common (e.g. invoices with an XML copy); only a risk if you open the attachment.", Low)
            };
            finding(Static, sev, "T1027.009 Embedded Payloads", title, why, format!("embedded file {text}"))
        }
        Ind::PdfJs => finding(Static, Medium, "T1059.007 JavaScript", "Runs JavaScript when opened", "Forms use scripts, but so do most PDF attacks. airlock ran it in a fake reader: anything harmful it tried is listed under its behaviour.", format!("JavaScript: {text}")),
        Ind::PdfJsClick => finding(Static, Low, "T1059.007 JavaScript", "JavaScript that only runs when you click or type", "Typical for interactive forms. Nothing runs by itself.", format!("JavaScript: {text}")),
        Ind::PdfJsForm => finding(Static, Info, "-", "Standard form-field scripts", "Fillable forms use Adobe's built-in functions to format numbers, dates and totals. Harmless.", text.to_string()),
        Ind::PdfUnreadable => finding(Static, Medium, "T1027 Obfuscated Files", if text.starts_with("password") { "Password protected" } else { "The PDF's structure could not be read" }, "Damaged or deliberately malformed files can hide things from scanners, so its contents could not be fully checked.", text.to_string()),
        Ind::PdfFeature => {
            let t = text.to_ascii_lowercase();
            let (title, why, sev, att) = if t.starts_with("encryption") {
                ("Encrypted", "Usually just sets permissions such as \"no printing\". Not a risk by itself.", Info, "-")
            } else if t.contains("xfa") {
                ("Uses an XFA form", "An older Adobe form technology. Legitimate, but it was the entry point for several reader exploits.", Low, "-")
            } else if t.contains("embedded media") {
                ("Contains a video or sound player", "Media players in PDFs were once a common exploit target; modern readers handle them safely.", Low, "-")
            } else if t.contains("flash") || t.contains("rich media") {
                ("Contains Flash or rich media", "Flash content in PDFs was one of the most exploited features ever; modern readers no longer play it.", Medium, "T1203 Exploitation for Client Execution")
            } else if t.starts_with("javascript") {
                ("Contains JavaScript", "Seen by a rough scan only (the structure could not be read).", Medium, "T1059.007 JavaScript")
            } else if t.contains("launch") {
                ("May start programs", "Seen by a rough scan only (the structure could not be read).", High, "T1204.002 Malicious File")
            } else if t.contains("on open") || t.contains("automatic") || t.contains("embedded") {
                ("Contains automatic actions or attachments", "Seen by a rough scan only (the structure could not be read).", Medium, "T1204.002 Malicious File")
            } else {
                ("Contains an unusual PDF feature", "Seen by a rough scan only (the structure could not be read).", Low, "-")
            };
            finding(Static, sev, att, title, why, format!("contains {text}"))
        }
        Ind::PdfUri if text.starts_with("mailto:") => finding(Static, Info, "-", "Email link", "Clicking it opens your mail program.", format!("email link {text}")),
        Ind::PdfUri | Ind::OfficeLink if link_risk(text).is_some() => {
            let (title, why) = link_risk(text).unwrap_or_default();
            finding(Static, Medium, "T1566.002 Spearphishing Link", title, why, format!("link to {text}"))
        }
        Ind::PdfUri => finding(Static, Info, "T1566.002 Spearphishing Link", "Link to a website", "An ordinary clickable link. Check where it really goes before clicking.", format!("link to {text}")),
        // Compressed object streams are how modern PDF writers save files.
        Ind::PdfObfuscation if text.contains("only visible after decompression") => finding(Static, Low, "T1027 Obfuscated Files", "Some contents are compressed", "Normal in modern PDFs; it also hides them from simple scanners.", text.to_string()),
        Ind::PdfObfuscation => finding(Static, Medium, "T1027 Obfuscated Files", "Disguises its contents from scanners", "Key words in the file are written in an encoded form that has no use except fooling security scanners.", text.to_string()),
        // ---- PDF JavaScript, run in the fake reader
        Ind::JsCall => {
            let (cat, rest) = text.split_once(": ").unwrap_or(("other", text));
            let click = rest.starts_with("(on user action");
            let (sev, att, verb, title, why) = match (cat, click) {
                ("net", false) => (High, "T1071.001 Web Protocols", "contacts the internet:", "Contacts the internet", "Its script tried to reach a server: typical for downloading malware or reporting back."),
                ("net", true) => (Low, "T1071.001 Web Protocols", "would open a website if clicked:", "A button opens a website", "Like a link: only when you click it."),
                ("launch", false) => (High, "T1204.002 Malicious File", "opens/launches:", "Tries to open or run something", "Its script tried to open another file or program."),
                ("launch", true) => (Medium, "T1204.002 Malicious File", "would open/launch if clicked:", "A button would open or run something", "Only when you click it, but documents rarely need to start anything."),
                ("drop", false) => (High, "T1105 Ingress Tool Transfer", "writes a file:", "Tries to save a file to your computer", "A classic way to plant malware."),
                ("drop", true) => (Medium, "T1105 Ingress Tool Transfer", "would write a file if clicked:", "A button would save a file to your computer", "Only when you click it."),
                ("persist", _) => (Medium, "T1546 Event Triggered Execution", "installs a hook:", "Sets itself up to run again later", "Malware does this to keep running."),
                ("priv", _) => (Medium, "T1068 Exploitation for Privilege Escalation", "privileged call:", "Uses privileged reader functions", "Functions meant for trusted documents only; attacks abuse them."),
                ("timer", _) => (Low, "-", "schedules code:", "Runs code on a timer", "Common in forms; also used to delay an attack."),
                ("ui", _) => (Info, "-", "shows UI:", "Shows a message or dialog", "Harmless by itself; can be used to trick you into clicking."),
                _ => (Info, "-", "calls", "Uses a reader function", "Recorded for completeness."),
            };
            finding(Emulated, sev, att, title, why, format!("{verb} {rest}"))
        }
        Ind::JsExploit => finding(Emulated, High, "T1203 Exploitation for Client Execution", "Exploit for a known PDF reader bug", WHY_EXPLOIT, format!("EXPLOIT: {text}")),
        Ind::JsEval => finding(Emulated, Low, "T1027 Obfuscated Files", "Unpacks hidden code", "The script builds more code at run time; attacks do this to hide what they do.", format!("unpacked layer: {text}")),
        Ind::JsError => finding(Emulated, Info, "-", "A script error", "Usually harmless (often a feature the fake reader does not imitate).", format!("script error: {text}")),
        // ---- Office
        Ind::OfficeMacro => finding(Static, Medium, "T1059.005 Visual Basic", "Contains macros", WHY_MACRO, format!("VBA macro {text}")),
        Ind::OfficeAutoExec => finding(Static, High, "T1204.002 Malicious File", "A macro runs automatically when opened", "If you click \"Enable content\" in Office, this code starts by itself. That is how most Office malware runs.", format!("macro runs automatically on open: {text}")),
        Ind::OfficeSuspicious => {
            let k = text.to_ascii_lowercase();
            let dangerous = [
                "shell", "urldownloadtofile", "powershell", "createprocess", "run", "exec", "wscript", "mshta", "certutil", "regsvr32", "rundll32",
                // script-host execution (see EXEC_PRIMITIVES in guest/office_triage.py)
                "scriptcontrol", "addcode", "callbyname", "macscript",
            ]
            .iter()
            .any(|d| k.split(':').next().unwrap_or("").contains(d));
            let (sev, title, why) = if dangerous {
                (High, "A macro can run commands or programs", "The macro code uses functions that start programs or download files: what a malware dropper does.")
            } else {
                (Medium, "A macro uses risky functions", "Functions often used by malware, but also by some legitimate macros.")
            };
            finding(Static, sev, "T1059.005 Visual Basic", title, why, format!("macro uses {text}"))
        }
        Ind::OfficeIoc => finding(Static, Medium, "T1105 Ingress Tool Transfer", "A macro mentions web addresses or files", "Addresses or program names inside macro code often show where malware would be downloaded from.", format!("macro mentions {text}")),
        Ind::OfficeObfuscation => finding(Static, Medium, "T1027 Obfuscated Files", "A macro hides what it does", "The macro encodes its text so it cannot be read at a glance, a common trick to slip past scanners.", format!("macro hides strings: {text}")),
        Ind::OfficeStomping => finding(Static, High, "T1564.007 VBA Stomping", "Hidden macro code", "The macro you would see in Office is a decoy; Office would actually run different, hidden code. Only done to deceive.", text.to_string()),
        Ind::OfficeXlm => finding(Static, High, "T1059 Command and Scripting Interpreter", "Old Excel 4.0 macros", "A 30-year-old macro language that many scanners miss; popular with malware for exactly that reason.", text.to_string()),
        Ind::OfficeExternal => {
            let (sev, att, title, why) = if text.starts_with("remote template") {
                (High, "T1221 Template Injection", "Downloads content from the internet when opened", "Office would fetch a template from a web address as soon as the file opens. Attackers use this to bring in macros or exploits from outside.")
            } else if text.starts_with("external image") {
                (Medium, "T1187 Forced Authentication", "Loads an image from the internet", "Opening it tells the sender you read it, and on Windows it can leak your login details to their server.")
            } else {
                (Medium, "T1221 Template Injection", "Links to outside content", "Office would load part of this document from another location.")
            };
            finding(Static, sev, att, title, why, text.to_string())
        }
        Ind::OfficeExploit => finding(Static, High, "T1203 Exploitation for Client Execution", "Known exploit technique", WHY_EXPLOIT, format!("EXPLOIT: {text}")),
        Ind::OfficeEmbedded if text.starts_with("hidden data after the end") => finding(Static, Medium, "T1027 Obfuscated Files", "Hides data after the end of the document", "Word stops reading where the document ends; the rest is invisible to you and a common place to smuggle a payload.", text.to_string()),
        Ind::OfficeEmbedded if text.starts_with("object set to load by itself") => finding(Static, Medium, "T1203 Exploitation for Client Execution", "An embedded object loads by itself", "Most embedded objects wait for a double-click; this one is loaded the moment the file opens, which is how many document exploits start.", text.to_string()),
        Ind::OfficeEmbedded => finding(Static, Medium, "T1027.009 Embedded Payloads", "Contains an embedded object", "Files or controls hidden inside the document; can carry a program.", text.to_string()),
        Ind::OfficeLink => finding(Static, Info, "T1566.002 Spearphishing Link", "Link to a website", "An ordinary clickable link. Check where it really goes before clicking.", format!("link to {text}")),
        Ind::OfficeContainer => finding(Static, Low, "-", "Macro-enabled file format", "This file type is allowed to carry macros.", text.to_string()),
        Ind::OfficeError => finding(Static, Info, "-", "Part of the file could not be analyzed", "Often a damaged or unusual file.", format!("triage: {text}")),
        // ---- known malware
        Ind::YaraHigh => finding(Signature, High, "-", "Matches known malware", "Its contents match a signature written for a specific malware family or exploit.", text.to_string()),
        Ind::YaraMedium => finding(Signature, Medium, "-", "Matches a suspicious pattern", "Its contents match a signature for a technique malware uses; legitimate files rarely match.", text.to_string()),
        Ind::YaraLow => finding(Signature, Low, "-", "Weak signature match", "A broad signature matched; often meaningless on its own.", text.to_string()),
        // ---- behaviour inside the VM
        Ind::Exec => finding(Monitor, High, "T1059 Command and Scripting Interpreter", "Tried to run a program", WHY_BLOCKED, format!("tried to run {text} (blocked)")),
        Ind::ProcessCreate => finding(Monitor, High, "T1203 Exploitation for Client Execution", "Tried to start another process", WHY_BLOCKED, format!("tried to start a process: {text} (blocked)")),
        Ind::Socket => finding(Monitor, Medium, "T1071 Application Layer Protocol", "Opened a network connection", "Document viewers have no reason to use the network.", format!("opened a network socket ({text})")),
        Ind::Connect => finding(Monitor, High, "T1071 Application Layer Protocol", "Tried to connect to the internet", "It only reached airlock's fake internet; the real one was never reachable.", format!("network: {text}")),
        Ind::KernelSurface => finding(Monitor, High, "T1068 Exploitation for Privilege Escalation", "Tried to attack the operating system", WHY_BLOCKED, format!("kernel attack-surface call {text} (blocked)")),
        Ind::Ptrace => finding(Monitor, High, "T1055 Process Injection", "Tried to tamper with another process", WHY_BLOCKED, format!("{text} (blocked)")),
        Ind::RendererAbnormal => finding(Monitor, Medium, "T1203 Exploitation for Client Execution", "The viewer crashed or hung", "Can be a sign of an exploit attempt, or just a damaged or very complex file.", text.to_string()),
        Ind::FileDropped => {
            let exe = ["[Linux executable", "[Windows executable", "[script]", "executable-bit", "SETUID"].iter().any(|k| text.contains(k));
            let (sev, title, why) = if exe {
                (High, "Left a program behind", "Something saved a program or script while the document was open: how malware gets installed. It stayed inside the destroyed VM.")
            } else {
                (Medium, "Left a file behind", "Something saved a file while the document was open. It stayed inside the destroyed VM.")
            };
            finding(Outside, sev, "T1105 Ingress Tool Transfer", title, why, format!("left on disk: {text}"))
        }
    }
}

/// Links of the kind phishing documents use: free web hosting and file
/// storage that anyone can publish to anonymously, bare IP addresses,
/// direct downloads of programs, Windows file shares. (title, explanation)
fn link_risk(url: &str) -> Option<(&'static str, &'static str)> {
    let u = url.trim().to_ascii_lowercase();
    // \\server\share or file://server/share (file:///C:/... is this computer).
    let file_host = u.strip_prefix("file://").map(|r| r.split(['/', '\\']).next().unwrap_or(""));
    if u.starts_with("\\\\") || file_host.is_some_and(|h| !h.is_empty() && h != "localhost") {
        return Some(("Links to a network file share", "On Windows, opening it can send your login details to whoever runs that server."));
    }
    let rest = u.split_once("://").map(|(_, r)| r)?;
    let host = rest.split(['/', '?', '#']).next().unwrap_or("").rsplit('@').next().unwrap_or("");
    let host = host.rsplit_once(':').filter(|(_, p)| p.bytes().all(|b| b.is_ascii_digit())).map_or(host, |(h, _)| h);
    let path = rest[rest.find('/').unwrap_or(rest.len())..].split(['?', '#']).next().unwrap_or("");
    const FREE_HOSTING: &[&str] = &[
        "vercel.app", "netlify.app", "pages.dev", "workers.dev", "r2.dev", "web.app", "firebaseapp.com", "firebasestorage.googleapis.com",
        "storage.googleapis.com", "blob.core.windows.net", "web.core.windows.net", "backblazeb2.com", "glitch.me",
        "herokuapp.com", "onrender.com", "replit.app", "replit.dev", "repl.co", "ngrok.io", "ngrok-free.app", "ngrok.app", "trycloudflare.com",
        "duckdns.org", "ddns.net", "000webhostapp.com", "surge.sh", "ipfs.io", "dweb.link", "cloudflare-ipfs.com", "fleek.co",
        "telegra.ph", "pastebin.com", "dropboxusercontent.com", "transfer.sh", "gofile.io", "files.catbox.moe", "cdn.discordapp.com",
    ];
    let on = |d: &str| host == d || host.ends_with(&format!(".{d}"));
    // Amazon S3 buckets (not every amazonaws.com service).
    let s3 = host.ends_with(".amazonaws.com") && (host.starts_with("s3.") || host.starts_with("s3-") || host.contains(".s3.") || host.contains(".s3-"));
    if host.parse::<std::net::Ipv4Addr>().is_ok() || host.starts_with('[') {
        return Some(("Link to a bare IP address", "Real organisations link to named websites; a raw number address is typical of malware servers."));
    }
    let program = [".exe", ".msi", ".scr", ".hta", ".jse", ".vbs", ".vbe", ".wsf", ".bat", ".cmd", ".ps1", ".lnk", ".iso", ".img", ".vhd", ".vhdx", ".jar", ".appx", ".msix", ".one", ".cpl", ".dll"];
    if program.iter().any(|e| path.ends_with(e)) {
        return Some(("Link downloads a program", "Clicking it would download something that runs as a program, not a document."));
    }
    if s3 || FREE_HOSTING.iter().any(|d| on(d)) {
        return Some((
            "Link to a free hosting or file-sharing site",
            "Anyone can publish there anonymously in minutes, so phishing documents use them for fake login and \"view document\" pages. Real companies rarely do.",
        ));
    }
    None
}

fn s(v: &serde_json::Value, k: &str) -> String {
    // The sinkhole already squashes strings; re-check, it parsed hostile input.
    let raw = v.get(k).and_then(|x| x.as_str()).unwrap_or("");
    raw.chars().take(200).map(|c| if (' '..='~').contains(&c) { c } else { '?' }).collect()
}

const WHY_NET: &str = "The document reached out to the internet. It only reached airlock's fake internet, which records what was asked for; the real internet was never reachable.";

fn sinkhole_findings(path: &Path) -> Vec<Finding> {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let mut out = Vec::new();
    for line in text.lines().take(2000) {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else { continue };
        let f = |attack, title: &str, what| finding(Source::Outside, Severity::High, attack, title, WHY_NET, what);
        match v.get("t").and_then(|t| t.as_str()) {
            Some("dns") => out.push(f("T1071.004 DNS", "Looked up a server on the internet", format!("DNS lookup of {}", s(&v, "name")))),
            Some("tcp") => {
                let dst = s(&v, "dst");
                let ev = match v.get("proto").and_then(|p| p.as_str()) {
                    Some("http") => f("T1105 Ingress Tool Transfer", "Tried to download something", format!("HTTP \"{}\" Host: {} (to {dst})", s(&v, "request"), s(&v, "host"))),
                    Some("tls") => f("T1573 Encrypted Channel", "Opened an encrypted connection", format!("TLS connection to {} ({dst})", s(&v, "sni"))),
                    _ => f("T1095 Non-Application Layer Protocol", "Connected to a server", format!("TCP connection to {dst} sent \"{}\"", s(&v, "first_bytes"))),
                };
                out.push(ev);
            }
            Some("flow") => {
                let flow = s(&v, "flow");
                // TCP and DNS are reported richer above.
                if !flow.starts_with("tcp ") && !flow.ends_with(":53") {
                    out.push(f("T1095 Non-Application Layer Protocol", "Sent network traffic", format!("packets: {flow}")));
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

/// The verdict for people: what it is, and what to do.
pub struct Verdict {
    /// Stable machine label ("LIKELY MALICIOUS").
    pub label: &'static str,
    /// Plain headline ("Very likely an attack").
    pub headline: &'static str,
    pub summary: &'static str,
    pub advice: &'static str,
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
            findings.push(finding(
                Source::Outside,
                Severity::High,
                "T1203 Exploitation for Client Execution",
                "The virtual machine behaved abnormally",
                "The VM stopped following airlock's rules, which is what a successful exploit looks like from outside. It was shut down.",
                what.clone(),
            ));
        }
        // Scripts that run on open were run in the fake reader. If they did
        // nothing risky there (and ran without errors), they are form logic.
        // (What happens only on a click is reported on its own.)
        let emulated_risk = findings
            .iter()
            .any(|f| f.source == Source::Emulated && ((f.severity >= Severity::Low && !f.what.contains("(on user action")) || (f.what.starts_with("script error") && !f.what.contains("(on user action"))));
        if !emulated_risk {
            for f in findings.iter_mut().filter(|f| f.title == "Runs JavaScript when opened") {
                f.severity = Severity::Low;
                f.title = "Runs JavaScript when opened (nothing risky)".into();
                f.explain = "airlock ran it in a fake Adobe Reader: it did not touch the internet, files or programs, and hid nothing. Typical for forms (filling in dates, totals, checks).";
            }
        }
        let mut seen = std::collections::HashSet::new();
        findings.retain(|f| seen.insert(f.what.clone()));
        findings.sort_by(|a, b| b.severity.cmp(&a.severity));
        Report { findings }
    }

    pub fn verdict(&self) -> Verdict {
        let behaviour = |sev| self.findings.iter().any(|f| !matches!(f.source, Source::Static | Source::Signature) && f.severity >= sev);
        // Emulated = what it *would* do in a real reader: that is behaviour.
        let static_sev = self.findings.iter().filter(|f| matches!(f.source, Source::Static | Source::Signature)).map(|f| f.severity).max();
        let has = |att: &str| self.findings.iter().any(|f| f.source == Source::Static && f.severity == Severity::High && f.attack.starts_with(att));
        // Decisive static evidence: we never run macros, so these stand on their own.
        let decisive = has("T1203") || has("T1564.007") || has("T1221") || (has("T1204.002") && has("T1059")) || has("T1027.009")
            // A PDF that starts a program by itself.
            || self.findings.iter().any(|f| f.source == Source::Static && f.severity == Severity::High && f.what.starts_with("automatic action Launch"))
            // A rule written for a known malware family or exploit.
            || self.findings.iter().any(|f| f.source == Source::Signature && f.severity == Severity::High);
        if behaviour(Severity::High) {
            Verdict {
                label: "MALICIOUS BEHAVIOUR",
                headline: "Dangerous: this file attacks the computer that opens it",
                summary: "the document actively tried things a document should never do",
                advice: "Do not open the original in any other program. Delete it. If it came by email, report it as phishing and warn the sender through another channel: their account may be compromised.",
            }
        } else if decisive {
            Verdict {
                label: "LIKELY MALICIOUS",
                headline: "Very likely an attack",
                summary: "contains an auto-running payload, a known exploit technique or known malware (not executed here)",
                advice: "Do not open the original in Office or a PDF reader, and never click \"Enable content\" or \"Enable editing\". Delete it unless you can confirm with the sender, by phone or a separate message, that it is genuine.",
            }
        } else if behaviour(Severity::Medium) || static_sev >= Some(Severity::Medium) {
            Verdict {
                label: "SUSPICIOUS",
                headline: "Be careful",
                summary: "risky features or odd behaviour, but no clear attack observed",
                advice: "Reading it in airlock is safe. Open the original elsewhere only if you trust where it came from; to keep or share it, use Save > Safe PDF copy.",
            }
        } else {
            Verdict {
                label: "NO ACTIVE BEHAVIOUR OBSERVED",
                headline: "No threats found",
                summary: "nothing suspicious seen — this is not a guarantee of safety",
                advice: "Nothing risky was found. No scanner can promise a file is safe, so the Safe PDF copy is still the safest version to keep or share.",
            }
        }
    }

    /// The report as plain text: verdict and advice, findings by severity
    /// in plain words, technical evidence under each.
    pub fn to_text(&self) -> String {
        let v = self.verdict();
        let mut t = format!("airlock report: {}\n{}\n\nWhat to do: {}\n", v.label, v.headline, v.advice);
        let important: Vec<_> = self.findings.iter().filter(|f| f.severity > Severity::Info).collect();
        let notes: Vec<_> = self.findings.iter().filter(|f| f.severity == Severity::Info).collect();
        if !important.is_empty() {
            t += "\nFindings:\n";
        }
        // One entry per kind of finding; every piece of evidence under it.
        let mut groups: Vec<(&Finding, Vec<&Finding>)> = Vec::new();
        for f in important {
            match groups.iter_mut().find(|(g, _)| g.title == f.title && g.severity == f.severity && g.source == f.source) {
                Some((_, all)) => all.push(f),
                None => groups.push((f, vec![f])),
            }
        }
        for (f, all) in groups {
            let tag = match f.severity {
                Severity::High => "HIGH",
                Severity::Medium => "MED ",
                _ => "LOW ",
            };
            t += &format!("\n  [{tag}] {}\n         {}\n", f.title, f.explain);
            for e in &all {
                t += &format!("         evidence: {}\n", e.what);
            }
            t += &format!("         seen by: {}", f.source.describe());
            if f.attack != "-" {
                t += &format!(" · ATT&CK {}", f.attack);
            }
            t += "\n";
        }
        if !notes.is_empty() {
            t += "\nAlso noted (harmless on their own):\n";
            for f in notes {
                t += &format!("  - {}: {}\n", f.title, f.what);
            }
        }
        if self.findings.is_empty() {
            t += "\n(no findings)\n";
        }
        t
    }

    pub fn print(&self) {
        let v = self.verdict();
        // The first line is what scripts parse.
        eprintln!("\n=== airlock report: {} ===\n    {}", v.label, v.summary);
        eprintln!("\n{}", self.to_text().lines().skip(1).collect::<Vec<_>>().join("\n"));
        eprintln!();
    }

    pub fn to_json(&self) -> serde_json::Value {
        let v = self.verdict();
        serde_json::json!({
            "verdict": v.label,
            "headline": v.headline,
            "summary": v.summary,
            "advice": v.advice,
            "text": self.to_text(),
            "findings": self.findings.iter().map(|f| serde_json::json!({
                "source": format!("{:?}", f.source).to_lowercase(),
                "seen_by": f.source.describe(),
                "severity": format!("{:?}", f.severity).to_lowercase(),
                "attack": f.attack,
                "title": f.title,
                "explain": f.explain,
                "what": f.what,
            })).collect::<Vec<_>>()
        })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn phishing_style_links_stand_out() {
        use super::link_risk;
        for risky in [
            "https://update-two-tau.vercel.app/payment-receipt",
            "https://cleavemornedocs.s3.us-east-005.backblazeb2.com/x.html",
            "https://mybucket.s3.amazonaws.com/login.html",
            "http://185.12.3.4/doc",
            "https://example.com/invoice.pdf.exe?x=1",
            "\\\\attacker\\share\\a.docx",
            "HTTPS://User@Evil.Workers.Dev:8443/a",
            "file://fileserver/share/doc.pdf",
        ] {
            assert!(link_risk(risky).is_some(), "{risky}");
        }
        for fine in [
            "https://www.example.com/terms",
            "https://uc1.1c.ru/course/lid-1c-map/",
            "https://console.aws.amazon.com/",
            "https://lambda.us-east-1.amazonaws.com/x",
            "https://notvercel.app.example.org/",
            "mailto:a@b.c",
            "https://example.com/setup-guide.pdf",
            "https://github.com/mozilla/pdf.js",
            "file:///C:/Users/me/report.pdf",
            "file://localhost/etc/x",
        ] {
            assert!(link_risk(fine).is_none(), "{fine}");
        }
    }

    use super::*;

    fn title(ind: Ind, text: &str) -> (Severity, String) {
        let f = guest_finding(ind, text);
        (f.severity, f.title)
    }

    #[test]
    fn launch_is_rated_by_its_target() {
        assert_eq!(title(Ind::PdfAutoAction, "Launch: cmd.exe /c calc [document opened]").0, Severity::High);
        assert_eq!(title(Ind::PdfAutoAction, "Launch:  [document opened]").0, Severity::High);
        assert_eq!(title(Ind::PdfAutoAction, "Launch: manual.pdf [document opened]").1, "Opens another file by itself");
        assert_eq!(title(Ind::PdfClickAction, "Launch: invoice.pdf.exe [link or button clicked (page 1)]").0, Severity::Medium);
        assert_eq!(title(Ind::PdfClickAction, "Launch: chapter2.pdf [link or button clicked (page 1)]").0, Severity::Low);
    }

    #[test]
    fn quiet_scripts_are_low_noisy_ones_stay() {
        let js = (Ind::PdfJs, "[document opened (/OpenAction)] this.print(true);".to_string());
        let quiet = Report::build(&[js.clone()], None, &[]);
        assert_eq!(quiet.findings[0].severity, Severity::Low);
        assert_eq!(quiet.verdict().label, "NO ACTIVE BEHAVIOUR OBSERVED");
        let noisy = Report::build(&[js.clone(), (Ind::JsEval, "eval of 300 chars".into())], None, &[]);
        assert!(noisy.findings.iter().any(|f| f.title == "Runs JavaScript when opened" && f.severity == Severity::Medium));
        let failed = Report::build(&[js, (Ind::JsError, "ReferenceError: x".into())], None, &[]);
        assert_eq!(failed.verdict().label, "SUSPICIOUS");
    }
}
