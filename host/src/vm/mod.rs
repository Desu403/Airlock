//! One disposable VM per document: Firecracker on Linux (firecracker.rs),
//! QEMU on Windows (qemu.rs). What both share is here.

use anyhow::Result;
use std::fs;
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
mod firecracker;
#[cfg(target_os = "linux")]
pub use firecracker::*;
#[cfg(windows)]
mod qemu;
#[cfg(windows)]
pub use qemu::*;

/// Packs the untrusted bytes into a raw disk: header + bytes + padding.
/// The host never interprets the document itself.
pub fn write_doc_disk(dir: &Path, doc: &[u8]) -> Result<PathBuf> {
    let mut img = Vec::with_capacity(doc.len() + 1024);
    img.extend_from_slice(&airlock_proto::DOC_MAGIC);
    img.extend_from_slice(&(doc.len() as u64).to_le_bytes());
    img.extend_from_slice(doc);
    img.resize(img.len().div_ceil(512) * 512, 0);
    let p = dir.join("doc.img");
    fs::write(&p, img)?;
    Ok(p)
}

pub struct Drive {
    pub id: &'static str,
    pub path: PathBuf,
    pub read_only: bool,
}

pub struct Spec {
    pub mode: &'static str,
    /// Extra drives after the root filesystem (vdb, vdc, ...).
    pub drives: Vec<Drive>,
    /// Wire a NIC to the sinkhole; events are written to this file.
    pub sinkhole_events: Option<PathBuf>,
    /// Extra kernel command line options for the agent (fixed strings only).
    pub options: &'static [&'static str],
    /// The file's extension ("cpp", "jpg"): which language to colour, as the
    /// document disk carries no name. Only [a-z0-9]{1,8} reaches the VM.
    pub ext: Option<String>,
    /// A file inside an archive to open (its index among the files): that VM
    /// unpacks it from the archive by itself.
    pub entry: Option<u32>,
}

/// "Report.CPP" -> Some("cpp"); anything else (no dot, odd characters) -> None.
pub fn ext_hint(name: &str) -> Option<String> {
    let (_, ext) = name.rsplit_once('.')?;
    let ext = ext.to_ascii_lowercase();
    (1..=8).contains(&ext.len()).then_some(()).filter(|_| ext.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())).map(|_| ext)
}

/// Guest console output is attacker-controlled text: strip anything that
/// could drive a terminal before a human ever sees it.
pub fn sanitized_log(log: &Path) -> String {
    let raw = fs::read(log).unwrap_or_default();
    raw.iter()
        .map(|&b| match b {
            b'\n' => '\n',
            0x20..=0x7e => b as char,
            _ => '?',
        })
        .collect()
}
