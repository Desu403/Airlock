//! ClamAV (Cisco Talos's open-source engine) in the analysis VM: its signed
//! database arrives on a read-only disk (vdd, mounted at SIGS) and the file is
//! scanned by `clamscan`, which also looks inside archives and Office files.

use crate::monitor::{self, Net, Opts};
use airlock_proto::Ind;
use std::time::Duration;

pub const SIGS: &str = "/run/sigs";

/// Whether the database disk was mounted (analysis VMs only, when the host has one).
pub fn available() -> bool {
    std::path::Path::new(SIGS).join("main.cvd").exists() || std::path::Path::new(SIGS).join("main.cld").exists()
}

/// "path: Win.Trojan.Agent-123 FOUND" -> the signature names.
pub fn scan(path: &str, work: &str) -> Vec<(Ind, String)> {
    if !available() {
        return Vec::new();
    }
    let logf = format!("{work}/clamscan.log");
    let log_arg = format!("--log={logf}");
    let argv = ["/usr/bin/clamscan", "--no-summary", "--infected", "--stdout", &log_arg, "--database", SIGS, "--max-filesize=256M", "--max-scansize=512M", "--max-recursion=8", path];
    // Loading ~8 million signatures takes a while and most of the VM's memory.
    let r = monitor::run(&argv, work, &Opts { mem_limit: None, ..Opts::new(Net::Deny, Duration::from_secs(180)) });
    let mut out = r.events;
    // Results come from ClamAV's own log file: inside the VM its standard
    // output reaches us empty.
    let stdout = std::fs::read_to_string(&logf).unwrap_or_else(|_| String::from_utf8_lossy(&r.stdout.unwrap_or_default()).into_owned());
    let _ = std::fs::remove_file(&logf);
    if !stdout.contains(" FOUND") {
        // Why nothing was found, if ClamAV said so (for the console log).
        for l in stdout.lines().filter(|l| !l.trim().is_empty()).take(4) {
            crate::log(&format!("clamav: {}", l.chars().take(160).collect::<String>()));
        }
        crate::log(&format!("clamav: {} event(s) from the monitor", out.len()));

    }
    for line in stdout.lines() {
        let Some(rest) = line.strip_suffix(" FOUND") else { continue };
        let name = rest.rsplit_once(": ").map_or(rest, |(_, n)| n).trim();
        if !name.is_empty() && name.len() < 200 {
            out.push((Ind::ClamAv, name.to_string()));
        }
    }
    out
}
