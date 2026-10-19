//! Known malware by fingerprint: the file's SHA-256 looked up in a local copy
//! of MalwareBazaar's list (scripts/known-malware.sh, next to the VM image).
//! A pure number comparison: the document is not parsed, nothing is sent.

use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;

/// The list next to the VM's image; none if it was never fetched. Turned off
/// by AIRLOCK_NO_KNOWN_LIST (the bench measures airlock's own detection on
/// samples that all come from MalwareBazaar).
fn list() -> Option<PathBuf> {
    if std::env::var_os("AIRLOCK_NO_KNOWN_LIST").is_some() {
        return None;
    }
    let dir = crate::vm::Assets::locate().ok()?.rootfs.parent()?.to_path_buf();
    Some(dir.join("known-malware.bin")).filter(|p| p.is_file())
}

pub fn sha256(doc: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(doc).into()
}

pub fn hex(h: &[u8; 32]) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}

/// Binary search over sorted 32-byte records, reading only what it needs.
fn contains(path: &std::path::Path, h: &[u8; 32]) -> std::io::Result<bool> {
    let mut f = std::fs::File::open(path)?;
    let n = f.metadata()?.len() / 32;
    let (mut lo, mut hi) = (0u64, n);
    let mut rec = [0u8; 32];
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        f.seek(SeekFrom::Start(mid * 32))?;
        f.read_exact(&mut rec)?;
        match rec.cmp(h) {
            std::cmp::Ordering::Equal => return Ok(true),
            std::cmp::Ordering::Less => lo = mid + 1,
            std::cmp::Ordering::Greater => hi = mid,
        }
    }
    Ok(false)
}

/// The fingerprint and list size when `doc` is known malware.
pub fn lookup(doc: &[u8]) -> Option<(String, u64)> {
    let path = list()?;
    let h = sha256(doc);
    if !contains(&path, &h).ok()? {
        return None;
    }
    let count = std::fs::metadata(&path).map(|m| m.len() / 32).unwrap_or(0);
    Some((hex(&h), count))
}

/// How many fingerprints the local list has, and when it was refreshed.
pub fn status() -> Option<(u64, u64)> {
    let path = list()?;
    let info = std::fs::read_to_string(path.with_extension("info")).unwrap_or_default();
    let updated = info.split_whitespace().skip_while(|w| *w != "updated").nth(1).and_then(|v| v.parse().ok()).unwrap_or(0);
    Some((std::fs::metadata(&path).ok()?.len() / 32, updated))
}

/// "HTTP://Example.COM/a/" -> "http://example.com/a": scheme and host are
/// case-insensitive, a trailing slash means the same address.
fn normalize(url: &str) -> Option<String> {
    let url = url.trim().trim_end_matches(['"', '\'', ')', '>', ',', '.']);
    let (scheme, rest) = url.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let (host, path) = rest.split_once('/').map_or((rest, ""), |(h, p)| (h, p));
    let out = format!("{scheme}://{}/{path}", host.to_ascii_lowercase());
    Some(out.trim_end_matches('/').to_string())
}

fn host_part(norm: &str) -> &str {
    norm.split_once("://").map_or(norm, |(_, r)| r.split('/').next().unwrap_or(r))
}

/// Bare IP addresses (with or without a port) in URLhaus serve malware only;
/// named hosts are often hacked but legitimate sites, matched by full address.
fn is_ip_host(host: &str) -> bool {
    let h = host.rsplit_once(':').map_or(host, |(h, p)| if p.bytes().all(|b| b.is_ascii_digit()) { h } else { host });
    h.split('.').count() == 4 && h.split('.').all(|o| o.parse::<u8>().is_ok())
}

/// Web addresses in `text` (each "http..." up to a space) that URLhaus lists
/// as spreading malware now.
pub fn malware_urls(texts: &[&str]) -> Vec<String> {
    if std::env::var_os("AIRLOCK_NO_KNOWN_LIST").is_some() {
        return Vec::new();
    }
    let Some(dir) = crate::vm::Assets::locate().ok().and_then(|a| a.rootfs.parent().map(|p| p.to_path_buf())) else { return Vec::new() };
    let Ok(list) = std::fs::read_to_string(dir.join("urlhaus.txt")) else { return Vec::new() };
    let urls: std::collections::HashSet<String> = list.lines().filter_map(normalize).collect();
    let ip_hosts: std::collections::HashSet<String> = urls.iter().map(|u| host_part(u).to_string()).filter(|h| is_ip_host(h)).collect();
    let mut out = Vec::new();
    for t in texts {
        for (i, _) in t.match_indices("http") {
            let token: String = t[i..].chars().take_while(|c| !c.is_whitespace()).collect();
            let Some(n) = normalize(&token) else { continue };
            if (urls.contains(&n) || ip_hosts.contains(host_part(&n))) && !out.contains(&n) {
                out.push(n);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn search() {
        let dir = std::env::temp_dir().join(format!("airlock-known-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut hashes: Vec<[u8; 32]> = (0u8..200).map(|i| sha256(&[i])).collect();
        hashes.sort();
        let path = dir.join("known-malware.bin");
        std::fs::write(&path, hashes.concat()).unwrap();
        assert!(contains(&path, &sha256(&[7])).unwrap());
        assert!(contains(&path, &sha256(&[199])).unwrap());
        assert!(!contains(&path, &sha256(b"not in the list")).unwrap());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn urls() {
        assert_eq!(normalize("HTTP://Example.COM/a/").as_deref(), Some("http://example.com/a"));
        assert_eq!(normalize("ftp://x").as_deref(), None);
        assert!(is_ip_host("185.228.72.128") && is_ip_host("59.96.137.253:48155") && !is_ip_host("example.com"));
    }
}
