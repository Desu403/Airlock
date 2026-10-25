//! PID 1 inside the disposable microVM.
//!
//! Everything in here is considered *untrusted after the document is opened*:
//! the renderer may be exploited and may take over this VM. That is fine —
//! the only thing that leaves the VM is the fixed-format stream defined in
//! `airlock-proto`, and the VM is destroyed afterwards.
//!
//! Modes (kernel command line `airlock.mode=`):
//!   view     render pages, no network device, tmpfs scratch
//!   analyze  + static triage, renderer network goes to the host sinkhole,
//!            scratch disk kept for the autopsy VM
//!   selftest analyze + a simulated exploited renderer (see selftest.rs)
//!   autopsy  inspect a dead analysis VM's scratch disk (read-only)
//!   live     like view, but stays up and answers render/search/text requests

mod archive;
mod autopsy;
mod clamav;
mod email;
mod emulate;
mod live;
mod html;
mod lure;
mod media;
mod office;
mod monitor;
mod selftest;
mod triage;
mod yara;

use airlock_proto::{sanitize_into, Error, Header, Ind, Kind, DOC_HEADER_LEN, DOC_MAGIC, FRAME_PORT, MAX_DIM, MAX_PAGES, MAX_TEXT};
use monitor::Net;
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::FromRawFd;
use std::time::Duration;

const WORK: &str = "/tmp/work";
const PAGE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Mode {
    View,
    Analyze,
    Selftest,
    Autopsy,
    Live,
    /// ClamAV only, in a VM of its own next to the analysis VM: the document
    /// (vdb) and the signature disk (vdc), no network, no scratch disk.
    ClamAv,
}

fn log(msg: &str) {
    println!("airlock-agent: {msg}");
}

fn mount(src: &str, target: &str, fstype: &str, flags: libc::c_ulong, data: &str) -> bool {
    let _ = fs::create_dir_all(target);
    let c = |s: &str| CString::new(s).unwrap();
    let r = unsafe {
        libc::mount(c(src).as_ptr(), c(target).as_ptr(), c(fstype).as_ptr(), flags, c(data).as_ptr() as *const _)
    };
    // EBUSY: the kernel already mounted it (e.g. CONFIG_DEVTMPFS_MOUNT).
    if r != 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EBUSY) {
        log(&format!("mount {target} failed"));
        return false;
    }
    true
}

fn power_off() -> ! {
    unsafe {
        libc::sync();
        let t = CString::new("/tmp").unwrap();
        libc::umount2(t.as_ptr(), libc::MNT_DETACH);
        libc::sync();
        // Firecracker (with reboot=k) tears the VM down on guest reboot.
        libc::reboot(libc::RB_AUTOBOOT);
    }
    loop {
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// Ends the session: half-close, then wait (bounded) for the host to hang up
/// so nothing still in flight is lost when the VM disappears.
fn finish(out: File) -> ! {
    use std::os::fd::AsRawFd;
    unsafe {
        let fd = out.as_raw_fd();
        libc::shutdown(fd, libc::SHUT_WR);
        let tv = libc::timeval { tv_sec: 5, tv_usec: 0 };
        libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_RCVTIMEO, &tv as *const _ as *const _, std::mem::size_of::<libc::timeval>() as _);
        let mut b = [0u8; 16];
        while libc::read(fd, b.as_mut_ptr() as *mut _, b.len()) > 0 {}
    }
    power_off()
}

/// The connection to the host: vsock under Firecracker (Linux), a
/// virtio-serial port named "airlock" under QEMU (Windows, which has no
/// vsock; `airlock.link=serial`). Both carry the same frames.
fn host_link() -> std::io::Result<File> {
    if !fs::read_to_string("/proc/cmdline").unwrap_or_default().split_whitespace().any(|t| t == "airlock.link=serial") {
        return vsock_connect(FRAME_PORT);
    }
    // The port appears shortly after boot; its node is made by devtmpfs.
    for _ in 0..100 {
        for e in fs::read_dir("/sys/class/virtio-ports").into_iter().flatten().flatten() {
            if fs::read_to_string(e.path().join("name")).is_ok_and(|n| n.trim() == "airlock") {
                let dev = format!("/dev/{}", e.file_name().to_string_lossy());
                return fs::OpenOptions::new().read(true).write(true).open(dev);
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    Err(std::io::Error::other("no virtio-serial port named airlock"))
}

fn vsock_connect(port: u32) -> std::io::Result<File> {
    unsafe {
        let fd = libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut addr: libc::sockaddr_vm = std::mem::zeroed();
        addr.svm_family = libc::AF_VSOCK as _;
        addr.svm_port = port;
        addr.svm_cid = libc::VMADDR_CID_HOST;
        let r = libc::connect(fd, &addr as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_vm>() as _);
        if r != 0 {
            let e = std::io::Error::last_os_error();
            libc::close(fd);
            return Err(e);
        }
        Ok(File::from_raw_fd(fd))
    }
}

fn send(out: &mut File, kind: Kind, a: u32, b: u32, c: u32, payload: &[u8]) -> std::io::Result<()> {
    let h = Header { kind: kind as u32, a, b, c, len: payload.len() as u32 };
    out.write_all(&h.encode())?;
    out.write_all(payload)
}

/// Web links reported so far (for the phishing-content check).
static SENT_LINKS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

fn send_indicators(out: &mut File, events: &[(Ind, String)]) {
    let mut buf = [0u8; MAX_TEXT as usize];
    for (ind, text) in events {
        let link = match ind {
            Ind::PdfUri | Ind::OfficeLink => Some(text.as_str()),
            Ind::PdfLure => text.split_once(": ").map(|(_, u)| u),
            _ => None,
        };
        if let (Some(l), Ok(mut v)) = (link, SENT_LINKS.lock()) {
            if v.len() < 200 {
                v.push(l.to_string());
            }
        }
        let n = sanitize_into(text.as_bytes(), &mut buf);
        if send(out, Kind::Indicator, *ind as u32, 0, 0, &buf[..n]).is_err() {
            power_off();
        }
    }
}

/// Pages in a PDF (0 if unknown), via `mutool pages` under the monitor.
/// The archive file to open (kernel option airlock.entry=N, N < 100000).
fn entry_option() -> Option<usize> {
    let cmdline = fs::read_to_string("/proc/cmdline").ok()?;
    cmdline.split_whitespace().find_map(|t| t.strip_prefix("airlock.entry=")).and_then(|v| v.parse().ok()).filter(|n| *n < 100_000)
}

/// Analysis of an archive: every file inside (up to a budget) unpacked in
/// this VM, checked like a document of its own kind, then deleted again (the
/// autopsy would otherwise see it). Findings name the file they are about.
/// `extract`: (index among the files, entry) -> that file's bytes.
type Extract<'a> = dyn Fn(usize, &archive::Entry) -> (Vec<(Ind, String)>, Option<Vec<u8>>) + 'a;

fn scan_inside(entries: &[archive::Entry], extract: &Extract) -> Vec<(Ind, String)> {
    const MAX_FILES: usize = 64;
    const MAX_BYTES: u64 = 256 << 20;
    let mut out = Vec::new();
    let mut budget = MAX_BYTES;
    for (i, e) in archive::files(entries).into_iter().enumerate().filter(|(_, e)| !e.encrypted).take(MAX_FILES) {
        if e.size > budget {
            break;
        }
        let (events, bytes) = extract(i, e);
        out.extend(events);
        let Some(bytes) = bytes else { continue };
        budget = budget.saturating_sub(bytes.len() as u64);
        let path = format!("{WORK}/inner-{i}");
        if fs::write(&path, &bytes).is_err() {
            continue;
        }
        let found: Vec<(Ind, String)> = match office::detect(&bytes) {
            Some(office::Kind::Office(_)) => [office::triage(&path, WORK), yara::scan(WORK, &path, None, true)].concat(),
            Some(office::Kind::Pdf) => [triage::analyze(&bytes, WORK, &path).indicators, yara::scan(WORK, &path, None, false)].concat(),
            Some(office::Kind::Text) => [media::script_check(&bytes), html::check(&bytes), yara::scan(WORK, &path, None, false)].concat(),
            Some(office::Kind::Image(ext)) => [media::hidden_data(&bytes, ext), yara::scan(WORK, &path, None, false)].concat(),
            _ => yara::scan(WORK, &path, None, false),
        };
        let _ = fs::remove_file(&path);
        let name = e.path.clone();
        out.extend(found.into_iter().map(|(ind, text)| {
            // Script findings start with their kind ("lure: ..."): keep it first.
            let text = match (ind, text.split_once(": ")) {
                (Ind::Script, Some((k, rest))) => format!("{k}: in {name}: {rest}"),
                _ => format!("in {name}: {text}"),
            };
            (ind, text)
        }));
    }
    out
}

/// The file's extension from the host (kernel option airlock.ext=, only
/// [a-z0-9]{1,8}): which language to colour. Never used to decide the type.
fn ext_hint() -> Option<String> {
    let cmdline = fs::read_to_string("/proc/cmdline").ok()?;
    let e = cmdline.split_whitespace().find_map(|t| t.strip_prefix("airlock.ext="))?;
    (e.len() <= 8 && e.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())).then(|| e.to_string())
}

fn page_count(pdf: &str) -> u32 {
    let r = monitor::run(&["/usr/bin/mutool", "pages", pdf], WORK, &monitor::Opts::new(Net::Deny, Duration::from_secs(60)));
    r.stdout.map_or(0, |o| o.windows(14).filter(|w| w == b"<page pagenum=").count() as u32)
}

fn fail(out: &mut File, e: Error) -> ! {
    log(&format!("error: {e:?}"));
    let _ = send(out, Kind::Error, e as u32, 0, 0, &[]);
    match out.try_clone() {
        Ok(f) => finish(f),
        Err(_) => power_off(),
    }
}

/// Copies the document off the raw read-only disk.
fn load_document() -> Option<Vec<u8>> {
    let mut f = File::open("/dev/vdb").ok()?;
    let mut hdr = [0u8; DOC_HEADER_LEN];
    f.read_exact(&mut hdr).ok()?;
    if hdr[..8] != DOC_MAGIC {
        return None;
    }
    let len = u64::from_le_bytes(hdr[8..16].try_into().unwrap());
    if len == 0 || len > airlock_proto::MAX_ARCHIVE_BYTES {
        return None;
    }
    let mut doc = vec![0u8; len as usize];
    f.read_exact(&mut doc).ok()?;
    Some(doc)
}

/// Minimal PAM (P7) reader. Runs inside the untrusted VM, so robustness
/// matters more than strictness here.
fn pam_to_rgba(pam: &[u8]) -> Option<(u32, u32, Vec<u8>)> {
    let end = pam.windows(7).position(|w| w == b"ENDHDR\n")? + 7;
    let head = std::str::from_utf8(&pam[..end]).ok()?;
    let (mut w, mut h, mut depth) = (0u32, 0u32, 0u32);
    for line in head.lines() {
        let mut it = line.split_whitespace();
        match (it.next(), it.next()) {
            (Some("WIDTH"), Some(v)) => w = v.parse().ok()?,
            (Some("HEIGHT"), Some(v)) => h = v.parse().ok()?,
            (Some("DEPTH"), Some(v)) => depth = v.parse().ok()?,
            _ => {}
        }
    }
    if w == 0 || h == 0 || w > MAX_DIM || h > MAX_DIM || !(1..=4).contains(&depth) {
        return None;
    }
    let px = (w * h) as usize;
    let data = pam.get(end..end + px * depth as usize)?;
    let mut rgba = Vec::with_capacity(px * 4);
    for p in data.chunks_exact(depth as usize) {
        let (r, g, b, a) = match depth {
            1 => (p[0], p[0], p[0], 255),
            2 => (p[0], p[0], p[0], p[1]),
            3 => (p[0], p[1], p[2], 255),
            _ => (p[0], p[1], p[2], p[3]),
        };
        rgba.extend_from_slice(&[r, g, b, a]);
    }
    Some((w, h, rgba))
}

fn mode_from_cmdline() -> Mode {
    let cmdline = fs::read_to_string("/proc/cmdline").unwrap_or_default();
    match cmdline.split_whitespace().find_map(|t| t.strip_prefix("airlock.mode=")) {
        Some("analyze") => Mode::Analyze,
        Some("selftest") => Mode::Selftest,
        Some("autopsy") => Mode::Autopsy,
        Some("live") => Mode::Live,
        Some("clamav") => Mode::ClamAv,
        _ => Mode::View,
    }
}

fn autopsy(out: &mut File) -> ! {
    let ro = libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;
    if !mount("/dev/vdb", "/mnt", "ext4", ro, "") {
        fail(out, Error::Internal);
    }
    if mount("tmpfs", "/run", "tmpfs", libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC, "size=16m,mode=0755") {
        let _ = fs::create_dir_all(yara::SCRATCH);
    }
    let found = autopsy::inspect("/mnt");
    log(&format!("autopsy: {} finding(s)", found.len()));
    send_indicators(out, &found);
    let _ = send(out, Kind::Done, 0, 0, 0, &[]);
    match out.try_clone() {
        Ok(f) => finish(f),
        Err(_) => power_off(),
    }
}

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--payload") {
        selftest::payload();
        return;
    }

    let nosx = libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;
    mount("proc", "/proc", "proc", nosx, "");
    mount("sysfs", "/sys", "sysfs", nosx, "");
    mount("devtmpfs", "/dev", "devtmpfs", libc::MS_NOSUID | libc::MS_NOEXEC, "");
    let mode = mode_from_cmdline();
    log(&format!("mode {mode:?}"));

    let mut out = match host_link() {
        Ok(f) => f,
        Err(e) => {
            log(&format!("host connection failed: {e}"));
            power_off();
        }
    };
    if mode == Mode::Autopsy {
        autopsy(&mut out);
    }
    if fs::read_to_string("/proc/cmdline").unwrap_or_default().split_whitespace().any(|t| t == "airlock.crashtest") {
        log("crashtest: PID 1 exiting mid-session");
        let _ = send(&mut out, Kind::Hello, 1, 0, 0, &[]);
        std::process::exit(1);
    }

    // Scratch space: a real disk in analysis modes (kept for the autopsy VM),
    // memory otherwise. Never executable.
    let scratch = matches!(mode, Mode::Analyze | Mode::Selftest);
    if !(scratch && mount("/dev/vdc", "/tmp", "ext4", nosx, "")) {
        mount("tmpfs", "/tmp", "tmpfs", nosx, "size=1g,mode=1777");
    }
    unsafe {
        let t = CString::new("/tmp").unwrap();
        libc::chmod(t.as_ptr(), 0o1777);
    }
    // Airlock's own unpacked copies for the YARA scan: in memory, so the
    // autopsy (which inspects the scratch disk) sees only what the document
    // and its renderers left behind.
    if scratch && mount("tmpfs", "/run", "tmpfs", nosx, "size=256m,mode=0755") {
        // ClamAV's database, when the host attached one (read-only, never executable).
        let _ = fs::create_dir_all(clamav::SIGS);
        if !mount("/dev/vdd", clamav::SIGS, "ext4", libc::MS_RDONLY | nosx, "") {
            let _ = fs::remove_dir(clamav::SIGS);
        }
        let _ = fs::create_dir_all(yara::SCRATCH);
        unsafe {
            let p = CString::new(yara::SCRATCH).unwrap();
            libc::chown(p.as_ptr(), monitor::RENDER_UID, monitor::RENDER_GID);
        }
    }
    if mode == Mode::ClamAv && mount("tmpfs", "/run", "tmpfs", nosx, "size=16m,mode=0755") {
        let _ = fs::create_dir_all(clamav::SIGS);
        // ext4 (made by scripts/clamav-db.sh) or squashfs (made by airlock
        // itself where there is no mke2fs, e.g. on Windows).
        if !mount("/dev/vdc", clamav::SIGS, "ext4", libc::MS_RDONLY | nosx, "") && !mount("/dev/vdc", clamav::SIGS, "squashfs", libc::MS_RDONLY | nosx, "") {
            let _ = fs::remove_dir(clamav::SIGS);
        }
    }
    let net = if scratch { Net::AllowInet } else { Net::Deny };

    let mut doc = load_document().unwrap_or_else(|| fail(&mut out, Error::BadDocDisk));
    let mut kind = office::detect(&doc).unwrap_or_else(|| fail(&mut out, Error::UnsupportedType));
    log(&format!("document type {kind:?}"));
    let _ = fs::create_dir_all(WORK);
    unsafe {
        let p = CString::new(WORK).unwrap();
        libc::chown(p.as_ptr(), monitor::RENDER_UID, monitor::RENDER_GID);
    }
    // A file inside an archive (airlock.entry=N): unpacked here, in this VM,
    // then shown as the file it is. The host only ever had the archive.
    let mut entry_name: Option<String> = None;
    if let (office::Kind::Email, Some(n)) = (kind, entry_option()) {
        let mail = format!("{WORK}/email.eml");
        if fs::write(&mail, &doc).is_err() {
            fail(&mut out, Error::Internal);
        }
        let (events, page) = email::page(&mail, WORK, net);
        send_indicators(&mut out, &events);
        let Some(e) = page.entries.get(n) else { fail(&mut out, Error::RenderFailed) };
        let (events, bytes) = email::extract(&mail, n, WORK, net);
        send_indicators(&mut out, &events);
        let _ = fs::remove_file(&mail);
        doc = bytes.unwrap_or_else(|| fail(&mut out, Error::RenderFailed));
        kind = office::detect(&doc).unwrap_or_else(|| fail(&mut out, Error::UnsupportedType));
        log(&format!("opened attachment {} from the e-mail: {kind:?}", e.path));
        entry_name = Some(e.path.clone());
    }
    if let (office::Kind::Archive(ext), Some(n)) = (kind, entry_option()) {
        let archive = format!("{WORK}/archive.{ext}");
        if fs::write(&archive, &doc).is_err() {
            fail(&mut out, Error::Internal);
        }
        let (events, entries) = archive::list(&archive, WORK, net);
        send_indicators(&mut out, &events);
        let files = archive::files(&entries);
        let Some(e) = files.get(n) else { fail(&mut out, Error::RenderFailed) };
        let (events, bytes) = archive::extract(&archive, &e.path, WORK, net);
        send_indicators(&mut out, &events);
        let _ = fs::remove_file(&archive);
        doc = bytes.unwrap_or_else(|| fail(&mut out, Error::RenderFailed));
        kind = office::detect(&doc).unwrap_or_else(|| fail(&mut out, Error::UnsupportedType));
        log(&format!("opened {} from the archive: {kind:?}", e.path));
        entry_name = Some(e.path.clone());
    }
    let doc_path = match kind {
        office::Kind::Pdf => format!("{WORK}/doc.pdf"),
        office::Kind::Office(ext) => format!("{WORK}/office.{ext}"),
        office::Kind::Image(ext) => format!("{WORK}/image.{ext}"),
        office::Kind::Text => format!("{WORK}/source.txt"),
        office::Kind::Archive(ext) => format!("{WORK}/archive.{ext}"),
        office::Kind::Email => format!("{WORK}/email.eml"),
    };
    if fs::write(&doc_path, &doc).is_err() {
        fail(&mut out, Error::Internal);
    }

    // The analysis VM scans too when the host attached the database to it
    // (older hosts); current hosts run ClamAV in a VM of its own.
    if (scratch || mode == Mode::ClamAv) && clamav::available() {
        log("scanning with ClamAV");
        send_indicators(&mut out, &clamav::scan(&doc_path, WORK));
    }
    if mode == Mode::ClamAv {
        if !clamav::available() {
            fail(&mut out, Error::Internal);
        }
        let _ = send(&mut out, Kind::Hello, 0, 0, 0, &[]);
        let _ = send(&mut out, Kind::Done, 0, 0, 0, &[]);
        match out.try_clone() {
            Ok(f) => finish(f),
            Err(_) => power_off(),
        }
    }
    if mode == Mode::Selftest {
        log("selftest: running simulated exploited renderer");
        let r = monitor::run(&["/sbin/airlock-agent", "--payload"], WORK, &monitor::Opts::new(net, Duration::from_secs(40)));
        send_indicators(&mut out, &r.events);
    }
    let mut listing: Option<String> = None;
    let pdf_path = match kind {
        office::Kind::Pdf => {
            if scratch {
                let t = triage::analyze(&doc, WORK, &doc_path);
                send_indicators(&mut out, &t.indicators);
                log("scanning with YARA");
                send_indicators(&mut out, &yara::scan(WORK, &doc_path, Some(&format!("{WORK}/clean.pdf")), false));
                if !t.scripts.is_empty() {
                    log(&format!("emulating {} script(s)", t.scripts.len()));
                    send_indicators(&mut out, &emulate::run(&t, WORK));
                }
            }
            doc_path.clone()
        }
        office::Kind::Office(ext) => {
            if scratch {
                send_indicators(&mut out, &office::triage(&doc_path, WORK));
                log("scanning with YARA");
                send_indicators(&mut out, &yara::scan(WORK, &doc_path, None, true));
            }
            log("converting with LibreOffice");
            send_indicators(&mut out, &office::convert(&doc_path, WORK, net, ext));
            let pdf = format!("{WORK}/office.pdf");
            if !std::path::Path::new(&pdf).exists() {
                fail(&mut out, Error::RenderFailed);
            }
            pdf
        }
        office::Kind::Image(ext) => {
            if scratch {
                send_indicators(&mut out, &media::hidden_data(&doc, ext));
                log("scanning with YARA");
                send_indicators(&mut out, &yara::scan(WORK, &doc_path, None, false));
            }
            log(&format!("converting the {ext} picture"));
            let (events, pdf) = media::convert_image(&doc_path, ext, WORK, net);
            send_indicators(&mut out, &events);
            pdf.unwrap_or_else(|| fail(&mut out, Error::RenderFailed))
        }
        office::Kind::Text => {
            if scratch {
                send_indicators(&mut out, &media::script_check(&doc));
                send_indicators(&mut out, &html::check(&doc));
                log("scanning with YARA");
                send_indicators(&mut out, &yara::scan(WORK, &doc_path, None, false));
            }
            // Inside an archive the file's own name gives the language.
            let ext = entry_name.as_deref().and_then(|n| n.rsplit_once('.')).map(|(_, e)| e.to_ascii_lowercase()).filter(|e| e.len() <= 8 && e.bytes().all(|b| b.is_ascii_alphanumeric())).or_else(ext_hint);
            let (events, pdf, lang) = media::convert_text(&doc_path, ext.as_deref(), WORK, net);
            log(&format!("text shown as {lang}"));
            send_indicators(&mut out, &events);
            pdf.unwrap_or_else(|| fail(&mut out, Error::RenderFailed))
        }
        office::Kind::Archive(ext) => {
            let (events, entries) = archive::list(&doc_path, WORK, net);
            send_indicators(&mut out, &events);
            if scratch {
                send_indicators(&mut out, &archive::findings(&entries, ext));
                log("checking the files inside the archive");
                send_indicators(&mut out, &scan_inside(&entries, &|_, e| archive::extract(&doc_path, &e.path, WORK, net)));
            }
            listing = Some(archive::listing(&entries));
            let (events, pdf) = archive::page(&entries, ext, WORK, net);
            send_indicators(&mut out, &events);
            pdf.unwrap_or_else(|| fail(&mut out, Error::RenderFailed))
        }
        office::Kind::Email => {
            let (events, page) = email::page(&doc_path, WORK, net);
            send_indicators(&mut out, &events);
            // Links go through the same checks as a document's (report: link
            // risk, URLhaus).
            if scratch {
                // Only in the analysis: while viewing, the app counts anything
                // reported as something the document tried.
                let links: Vec<(Ind, String)> = page.links.iter().map(|u| (Ind::OfficeLink, u.clone())).collect();
                send_indicators(&mut out, &links);
                // The phishing checks on the page (lure.rs) compare its wording
                // with where its links go.
                if let Ok(mut l) = SENT_LINKS.lock() {
                    l.extend(page.links.iter().cloned());
                }
                send_indicators(&mut out, &archive::findings(&page.entries, "e-mail"));
                send_indicators(&mut out, &html::check(&doc));
                log("checking the e-mail's attachments");
                send_indicators(&mut out, &scan_inside(&page.entries, &|i, _| email::extract(&doc_path, i, WORK, net)));
            }
            listing = Some(archive::listing(&page.entries));
            page.pdf.unwrap_or_else(|| fail(&mut out, Error::RenderFailed))
        }
    };
    drop(doc);
    // Phishing content: what the first pages show (QR codes, wording),
    // checked against the links the document carries.
    if scratch {
        log("checking the pages for phishing content");
        let links: Vec<String> = SENT_LINKS.lock().map(|l| l.clone()).unwrap_or_default();
        let pages = page_count(&pdf_path);
        send_indicators(&mut out, &lure::check(&pdf_path, WORK, &links, pages));
    }
    if mode == Mode::Live {
        live::serve(out, &pdf_path, kind == office::Kind::Text, listing);
    }

    // Page count: `mutool pages` prints one <page pagenum=...> element per page.
    let r = monitor::run(&["/usr/bin/mutool", "pages", &pdf_path], WORK, &monitor::Opts::new(net, PAGE_TIMEOUT));
    send_indicators(&mut out, &r.events);
    let listing = r.stdout.unwrap_or_else(|| fail(&mut out, Error::RenderFailed));
    let count = listing.windows(14).filter(|w| w == b"<page pagenum=").count() as u32;
    if count == 0 {
        fail(&mut out, Error::RenderFailed);
    }
    if count > MAX_PAGES {
        fail(&mut out, Error::TooManyPages);
    }
    log(&format!("{count} pages"));
    if send(&mut out, Kind::Hello, count, 0, 0, &[]).is_err() {
        power_off();
    }

    for page in 1..=count {
        let n = page.to_string();
        let argv = ["/usr/bin/mutool", "draw", "-q", "-r", "110", "-w", "1700", "-h", "2400", "-c", "rgb", "-F", "pam", "-o", "-", &pdf_path, &n];
        let r = monitor::run(&argv, WORK, &monitor::Opts::new(net, PAGE_TIMEOUT));
        send_indicators(&mut out, &r.events);
        let pam = r.stdout.unwrap_or_else(|| fail(&mut out, Error::RenderFailed));
        let (w, h, rgba) = pam_to_rgba(&pam).unwrap_or_else(|| fail(&mut out, Error::RenderFailed));
        if send(&mut out, Kind::Page, page - 1, w, h, &rgba).is_err() {
            power_off();
        }
    }
    let _ = send(&mut out, Kind::Done, count, 0, 0, &[]);
    log("done");
    finish(out);
}
