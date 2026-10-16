//! Runs in a *second*, fresh microVM after the analysis VM is dead. The
//! analysis VM's scratch disk is mounted read-only, noexec, nosuid, nodev,
//! and we report everything on it that our own pipeline did not put there.
//! Nothing from the disk is ever executed or opened by a viewer.

use airlock_proto::Ind;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

/// Files the analysis VM itself writes.
const EXPECTED: &[&str] = &["/work", "/work/doc.pdf", "/work/clean.pdf", "/work/emulate.js", "/lost+found"];

fn sha256_hex(path: &Path) -> String {
    use sha2::{Digest, Sha256};
    match fs::read(path) {
        Ok(b) => {
            let d = Sha256::digest(&b);
            d.iter().take(8).map(|x| format!("{x:02x}")).collect()
        }
        Err(_) => "?".into(),
    }
}

fn kind_of(path: &Path) -> &'static str {
    let mut head = [0u8; 8];
    let n = fs::File::open(path).and_then(|mut f| std::io::Read::read(&mut f, &mut head)).unwrap_or(0);
    let h = &head[..n];
    if h.starts_with(b"\x7fELF") {
        "Linux executable (ELF)"
    } else if h.starts_with(b"MZ") {
        "Windows executable (PE)"
    } else if h.starts_with(b"#!") {
        "script"
    } else if h.starts_with(b"PK\x03\x04") {
        "zip archive"
    } else if h.starts_with(b"%PDF") {
        "PDF"
    } else {
        "data"
    }
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<(Ind, String)>, budget: &mut usize) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        if *budget == 0 {
            return;
        }
        let p = e.path();
        let rel = format!("/{}", p.strip_prefix(root).unwrap_or(&p).display());
        let Ok(m) = fs::symlink_metadata(&p) else { continue };
        let ft = m.file_type();
        if ft.is_dir() {
            if !EXPECTED.contains(&rel.as_str()) && !rel.starts_with("/work/lo-profile") {
                *budget -= 1;
                out.push((Ind::FileDropped, format!("directory {rel}")));
            }
            if rel != "/lost+found" {
                walk(root, &p, out, budget);
            }
            continue;
        }
        if EXPECTED.contains(&rel.as_str()) || (rel.starts_with("/work/office.") && !rel[13..].contains('/')) {
            continue;
        }
        // LibreOffice profile: compare with the pristine template from the image.
        // Settings churn is normal; new/changed macros (basic/) or executables are not.
        if let Some(sub) = rel.strip_prefix("/work/lo-profile/") {
            let suspicious_kind = matches!(kind_of(&p), "Linux executable (ELF)" | "Windows executable (PE)" | "script");
            let tpl = Path::new("/usr/lib/airlock/lo-profile-template").join(sub);
            let changed = fs::read(&tpl).ok() != fs::read(&p).ok();
            // user/pack/ holds LibreOffice's own backup copies of its libraries.
            let macro_area = (sub.contains("/basic/") || sub.contains("/Scripts/")) && !sub.starts_with("user/pack/");
            if !(suspicious_kind || (changed && macro_area)) {
                continue;
            }
        }
        *budget -= 1;
        let mode = m.permissions().mode();
        let mut flags = String::new();
        if mode & 0o111 != 0 {
            flags.push_str(" executable-bit");
        }
        if mode & 0o6000 != 0 {
            flags.push_str(" SETUID/SETGID");
        }
        let text = if ft.is_symlink() {
            let t = fs::read_link(&p).map(|t| t.display().to_string()).unwrap_or_default();
            format!("symlink {rel} -> {t}")
        } else if ft.is_file() {
            format!("{rel} {}B [{}]{flags} sha256:{}", m.size(), kind_of(&p), sha256_hex(&p))
        } else {
            format!("special file {rel}{flags}")
        };
        out.push((Ind::FileDropped, text));
    }
}

pub fn inspect(mountpoint: &str) -> Vec<(Ind, String)> {
    let mut out = Vec::new();
    let mut budget = 200;
    // Files can also land in the scratch root (= the analysis VM's /tmp).
    let root = Path::new(mountpoint);
    walk(root, root, &mut out, &mut budget);
    out
}
