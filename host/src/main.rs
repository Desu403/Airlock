use airlock_core::{analysis, live, pdf, report, session, vm};

use airlock_proto::MAX_DOC_BYTES;
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

const DPI: f32 = 110.0;

fn usage() -> ! {
    eprintln!(
        "usage:
  airlock view <document> [--out DIR] [-v]     render safely (no network at all)
  airlock analyze <document> [--out DIR] [-v]  render + watch behaviour + report
  airlock selftest [-v]                        prove the detectors fire
  airlock doctor                               check this machine can run airlock"
    );
    std::process::exit(2);
}

fn main() {
    if let Err(e) = run() {
        eprintln!("airlock: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let cmd = args.next().unwrap_or_else(|| usage());
    let (mut input, mut out_dir, mut verbose, mut report_only) = (None, None, false, false);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--out" => out_dir = Some(PathBuf::from(args.next().unwrap_or_else(|| usage()))),
            "--verbose" | "-v" => verbose = true,
            // Test bench: just report.json, no page images or safe copy.
            "--report-only" => report_only = true,
            _ if input.is_none() => input = Some(PathBuf::from(a)),
            _ => usage(),
        }
    }
    let default_out = |p: &Path| {
        let stem = p.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        PathBuf::from(format!("{stem}.airlock"))
    };
    match cmd.as_str() {
        "view" | "analyze" => {
            let input = input.unwrap_or_else(|| usage());
            let out = out_dir.unwrap_or_else(|| default_out(&input));
            let doc = read_doc(&input)?;
            if cmd == "view" {
                view(&doc, &out, verbose)
            } else {
                analyze(&doc, &out, verbose, "analyze", !report_only).map(|_| ())
            }
        }
        "doctor" => doctor(),
        "livecheck" => livecheck(&read_doc(&input.unwrap_or_else(|| usage()))?),
        "containment" => containment(&read_doc(&input.unwrap_or_else(|| usage()))?),
        "selftest" => selftest(out_dir.unwrap_or_else(|| PathBuf::from("selftest.airlock")), verbose),
        _ => usage(),
    }
}

fn read_doc(input: &Path) -> Result<Vec<u8>> {
    let meta = std::fs::metadata(input).with_context(|| format!("reading {}", input.display()))?;
    if meta.len() > MAX_DOC_BYTES {
        bail!("document larger than {} MiB", MAX_DOC_BYTES >> 20);
    }
    Ok(std::fs::read(input)?)
}

fn save_pages(pages: &[pdf::Page], out_dir: &Path) -> Result<()> {
    std::fs::create_dir_all(out_dir)?;
    for (i, p) in pages.iter().enumerate() {
        let f = std::io::BufWriter::new(std::fs::File::create(out_dir.join(format!("page-{:04}.png", i + 1)))?);
        let mut enc = png::Encoder::new(f, p.width, p.height);
        enc.set_color(png::ColorType::Rgb);
        enc.set_depth(png::BitDepth::Eight);
        enc.write_header()?.write_image_data(&p.rgb)?;
    }
    if !pages.is_empty() {
        std::fs::write(out_dir.join("safe.pdf"), pdf::write(pages, DPI))?;
    }
    Ok(())
}

fn view(doc: &[u8], out_dir: &Path, verbose: bool) -> Result<()> {
    let assets = vm::Assets::locate()?;
    let run = vm::RunDir::create("view")?;
    let doc_disk = vm::write_doc_disk(&run.path, doc)?;
    let spec = vm::Spec {
        mode: "view",
        drives: vec![vm::Drive { id: "doc", path: doc_disk, read_only: true }],
        sinkhole_events: None,
        options: &[],
    };
    let s = session::run(&assets, &run, &spec, verbose, true)?;
    if let Some(e) = s.guest_error {
        bail!("guest reported {e:?}");
    }
    if let Some(v) = &s.protocol_violation {
        bail!("{v} — guest treated as hostile, nothing saved");
    }
    eprintln!("airlock: rendered {} page(s) in an isolated microVM in {:.1}s", s.pages.len(), s.elapsed.as_secs_f32());
    if !s.indicators.is_empty() {
        report::Report::build(&s.indicators, None, &[]).print();
    }
    save_pages(&s.pages, out_dir)?;
    eprintln!("airlock: wrote {}/safe.pdf and page PNGs", out_dir.display());
    Ok(())
}

fn analyze(doc: &[u8], out_dir: &Path, verbose: bool, mode: &'static str, pages: bool) -> Result<report::Report> {
    let a = analysis::run(doc, mode, verbose, &|line| eprintln!("airlock: {line}"))?;
    let (rep, s) = (a.report, a.session);
    rep.print();
    std::fs::create_dir_all(out_dir)?;
    std::fs::write(out_dir.join("report.json"), serde_json::to_vec_pretty(&rep.to_json())?)?;
    if s.protocol_violation.is_none() && pages {
        save_pages(&s.pages, out_dir)?;
    }
    match s.guest_error {
        Some(e) => eprintln!("airlock: rendering failed ({e:?}); report saved to {}/report.json", out_dir.display()),
        None => eprintln!("airlock: wrote {}/report.json, safe.pdf and page PNGs", out_dir.display()),
    }
    Ok(rep)
}

fn selftest(out_dir: PathBuf, verbose: bool) -> Result<()> {
    eprintln!("airlock selftest: a simulated *exploited renderer* runs inside the VM and tries to");
    eprintln!("phone home, drop files, run a shell, fork, ptrace and attack the kernel.\n");
    let blank = pdf::write(&[pdf::Page { width: 200, height: 260, rgb: vec![255; 200 * 260 * 3] }], DPI);
    let rep = analyze(&blank, &out_dir, verbose, "selftest", true)?;
    let has = |needle: &str| rep.findings.iter().any(|f| f.what.contains(needle));
    let checks = [
        ("DNS lookup seen by the sinkhole", has("DNS lookup of c2.airlock-selftest.example")),
        ("HTTP download seen by the sinkhole", has("GET /stage2.bin")),
        ("TLS SNI seen by the sinkhole", has("TLS connection to update.airlock-selftest.example")),
        ("raw-IP backdoor connection seen", has("203.0.113.66:4444")),
        ("UDP exfiltration seen", has("udp 198.51.100.7:9999")),
        ("shell execution blocked + logged", has("tried to run /bin/sh")),
        ("process creation blocked + logged", has("tried to start a process")),
        ("ptrace blocked + logged", has("ptrace(")),
        ("kernel attack surface blocked + logged", has("unshare()") && has("bpf()")),
        ("dropped ELF found by autopsy VM", has("stage2") && has("[Linux executable (ELF)]")),
        ("dropped script found by autopsy VM", has(".persist.sh")),
        ("dropped file named by YARA (EICAR test file)", has("Malw_Eicar")),
    ];
    let mut failed = 0;
    eprintln!("selftest results:");
    for (name, ok) in checks {
        eprintln!("  {} {name}", if ok { "PASS" } else { "FAIL" });
        failed += !ok as usize;
    }
    if failed > 0 {
        bail!("{failed} selftest check(s) failed");
    }
    eprintln!("all {} checks passed", checks.len());
    Ok(())
}

/// Smoke test for live mode: boot, render, search, extract text + layout, quit.
fn livecheck(doc: &[u8]) -> Result<()> {
    // Opened from a thread that then exits, like the app's worker threads:
    // the VM must outlive it (it was once killed with that thread).
    let doc = doc.to_vec();
    let mut s = std::thread::spawn(move || live::LiveSession::open(&doc)).join().map_err(|_| anyhow::anyhow!("open thread panicked"))??;
    std::thread::sleep(std::time::Duration::from_millis(1500));
    anyhow::ensure!(s.alive(), "the VM died when the thread that started it exited");
    eprintln!("live: {} page(s), ready in {:.1}s", s.pages.len(), s.boot_time.as_secs_f32());
    let t = std::time::Instant::now();
    let p = s.render(0, 96)?;
    eprintln!("live: page 1 rendered {}x{} in {} ms", p.width, p.height, t.elapsed().as_millis());
    let t = std::time::Instant::now();
    let text = s.text(0)?;
    let word = text.split_whitespace().find(|w| w.chars().count() >= 4).unwrap_or("the").to_string();
    let hits = s.search(&word)?;
    eprintln!("live: search {word:?} -> {} hit(s) in {} ms; page 1 text {} chars", hits.len(), t.elapsed().as_millis(), text.chars().count());
    if let Some(h) = hits.first() {
        eprintln!("live: first hit page {} at {:?}", h.page + 1, h.rect);
    }
    let lines = s.lines(0)?;
    eprintln!("live: page 1 layout {} line(s){}", lines.len(), lines.first().map(|l| format!(", first {:?} at {:?}", l.text, l.rect)).unwrap_or_default());
    if !s.indicators.is_empty() {
        report::Report::build(&s.indicators, None, &[]).print();
    }
    s.close();
    eprintln!("live: VM destroyed");
    Ok(())
}

/// Proves the viewing VM's containment by making it hostile on purpose
/// (guest test hooks, see guest-agent/src/live.rs) and checking that the
/// host ends it every time, stays responsive, and keeps it within its size.
fn containment(doc: &[u8]) -> Result<()> {
    use std::time::{Duration, Instant};
    let open = |test: &str| -> Result<live::LiveSession> {
        std::env::set_var("AIRLOCK_GUEST_TEST", test);
        let s = live::LiveSession::open(doc);
        std::env::remove_var("AIRLOCK_GUEST_TEST");
        s
    };
    let gone = |s: &mut live::LiveSession| {
        let t = Instant::now();
        while s.alive() && t.elapsed() < Duration::from_secs(3) {
            std::thread::sleep(Duration::from_millis(20));
        }
        !s.alive()
    };

    // 1. Attack attempts while viewing: the tripwire ends the session.
    let mut s = open("attack")?;
    let e = s.render(0, 96).err().map(|e| format!("{e:#}")).unwrap_or_default();
    anyhow::ensure!(e.starts_with(live::TRIPWIRE), "attack: expected the tripwire, got {e:?}");
    anyhow::ensure!(gone(&mut s), "attack: the VM was still running after the tripwire");
    eprintln!("ok   attack while viewing -> tripwire, VM destroyed ({})", e.split(": ").nth(1).unwrap_or("").chars().take(70).collect::<String>());

    // 2. Junk instead of a page: treated as hostile.
    let mut s = open("garbage")?;
    let e = s.render(0, 96).err().map(|e| format!("{e:#}")).unwrap_or_default();
    anyhow::ensure!(e.starts_with("protocol violation"), "garbage: expected a protocol violation, got {e:?}");
    anyhow::ensure!(gone(&mut s), "garbage: the VM was still running");
    eprintln!("ok   junk sent to the host -> treated as hostile, VM destroyed");

    // 3. A fully compromised guest: forks, fills memory, spins every CPU.
    let mut s = open("stress")?;
    s.set_request_timeout(Duration::from_secs(12))?;
    let pids = s.jail_pids();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let watch = {
        let stop = stop.clone();
        std::thread::spawn(move || {
            // Host responsiveness: how late a 10 ms sleep wakes up; and the
            // jail's memory (all of its processes) and process count.
            let (mut worst_ms, mut peak_kib, mut peak_procs) = (0u128, 0u64, 0usize);
            while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                let t = Instant::now();
                std::thread::sleep(Duration::from_millis(10));
                worst_ms = worst_ms.max(t.elapsed().as_millis().saturating_sub(10));
                let live: Vec<u64> = pids
                    .iter()
                    .filter_map(|p| std::fs::read_to_string(format!("/proc/{p}/status")).ok())
                    .filter_map(|st| st.lines().find_map(|l| l.strip_prefix("VmRSS:")).and_then(|v| v.split_whitespace().next()?.parse().ok()))
                    .collect();
                peak_procs = peak_procs.max(live.len());
                peak_kib = peak_kib.max(live.iter().sum());
            }
            (worst_ms, peak_kib, peak_procs)
        })
    };
    let e = s.render(0, 96).err().map(|e| format!("{e:#}")).unwrap_or_default();
    let ended = gone(&mut s);
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let (worst_ms, peak_kib, peak_procs) = watch.join().map_err(|_| anyhow::anyhow!("watcher panicked"))?;
    anyhow::ensure!(e.starts_with(live::VM_STOPPED), "stress: expected the session to end, got {e:?}");
    anyhow::ensure!(ended, "stress: the VM was still running after it stopped answering");
    // The VM has 2048 MiB; Firecracker itself needs a little on top.
    anyhow::ensure!(peak_kib < (2048 + 256) * 1024, "stress: the VM used {} MiB on the host", peak_kib / 1024);
    anyhow::ensure!(worst_ms < 250, "stress: the host stalled for {worst_ms} ms");
    eprintln!(
        "ok   compromised guest (fork bomb, memory fill, all CPUs) -> host stayed responsive (worst delay {worst_ms} ms), VM at most {} MiB in {peak_procs} host processes, destroyed when it stopped answering",
        peak_kib / 1024
    );
    Ok(())
}

/// Reports how fresh the guest image is: stale renderers are the realistic risk.
fn image_age(rootfs: &std::path::Path) {
    const MAX_DAYS: u64 = 30;
    let info = std::fs::read_to_string(rootfs.with_extension("info")).unwrap_or_default();
    let built = info.lines().find_map(|l| l.strip_prefix("built ")).and_then(|t| t.trim().parse::<u64>().ok());
    let version = |pkg: &str| {
        info.lines()
            .find_map(|l| l.strip_prefix(pkg).and_then(|v| v.strip_prefix('-')).filter(|v| v.starts_with(|c: char| c.is_ascii_digit())))
            .map(|v| v.rsplit_once("-r").map_or(v, |(ver, _)| ver).to_string())
            .unwrap_or_else(|| "?".into())
    };
    let Some(built) = built else {
        eprintln!("  warn  guest image age unknown\n        fix: scripts/update.sh (rebuilds it with current security fixes)");
        return;
    };
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let days = now.saturating_sub(built) / 86_400;
    let mut what = format!("MuPDF {}, LibreOffice {}", version("mupdf-tools"), version("libreoffice-common"));
    // "rules yara-forge-rules-core-20261011 5140"
    if let Some(r) = info.lines().find_map(|l| l.strip_prefix("rules ")) {
        if let Some((pkg, n)) = r.split_once(' ') {
            what += &format!(", {} YARA rules from {}", n.trim(), pkg.rsplit('-').next().unwrap_or(pkg));
        }
    }
    if days > MAX_DAYS {
        eprintln!("  warn  guest image is {days} days old ({what})\n        fix: scripts/update.sh (security fixes for the renderers, kernel and VMM)");
    } else {
        eprintln!("  ok    guest image built {days} day(s) ago ({what})");
    }
}

/// Checks everything airlock needs on this machine, with a fix for each miss.
/// Days since the running kernel was built (`uname -v` ends with its date,
/// e.g. "#1 SMP PREEMPT_DYNAMIC Sat, 11 Oct 2026 10:12:13 +0000").
fn host_kernel_age_days() -> Option<u64> {
    let v = std::fs::read_to_string("/proc/sys/kernel/version").ok()?;
    let words: Vec<&str> = v.split_whitespace().collect();
    let year: i64 = words.iter().rev().find_map(|w| w.parse().ok().filter(|y| (2000..2200).contains(y)))?;
    let yi = words.iter().rposition(|w| w.parse::<i64>().ok() == Some(year))?;
    let months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    // "... 11 Oct 2026 ..." or "... Oct 11 10:12:13 UTC 2026"
    let (day, month) = words[..yi].iter().rev().take(4).fold((None, None), |(d, m), w| {
        let w = w.trim_end_matches(',');
        (d.or(w.parse::<i64>().ok().filter(|n| (1..=31).contains(n))), m.or(months.iter().position(|x| *x == w).map(|i| i as i64 + 1)))
    });
    let (day, month) = (day?, month?);
    // Days since 1970 (civil-from-days inverse, proleptic Gregorian).
    let days = |y: i64, m: i64, d: i64| {
        let y = if m <= 2 { y - 1 } else { y };
        let era = y.div_euclid(400);
        let yoe = y - era * 400;
        let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
        era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719468
    };
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).ok()?.as_secs() as i64 / 86400;
    u64::try_from(now - days(year, month, day)).ok()
}

fn doctor() -> Result<()> {
    use std::process::{Command, Stdio};
    let quiet = |c: &mut Command| c.stdout(Stdio::null()).stderr(Stdio::null()).status().is_ok_and(|s| s.success());
    let has = |cmd: &str| quiet(Command::new("sh").args(["-c", &format!("command -v {cmd}")]));
    let rw = |p: &str| std::fs::OpenOptions::new().read(true).write(true).open(p).is_ok();
    let mut failed = 0;
    let mut check = |ok: bool, what: &str, fix: &str| {
        if ok {
            eprintln!("  ok    {what}");
        } else {
            eprintln!("  FAIL  {what}\n        fix: {fix}");
            failed += 1;
        }
    };
    eprintln!("airlock doctor\n");
    check(std::env::consts::ARCH == "x86_64", "x86_64 CPU", "only x86_64 is supported for now");
    check(rw("/dev/kvm"), "read/write access to /dev/kvm", "enable virtualisation (VT-x/AMD-V) in firmware and add yourself to the 'kvm' group, then log in again");
    check(has("bwrap"), "bubblewrap (bwrap)", "install your distribution's bubblewrap package");
    check(
        quiet(Command::new("bwrap").args(["--unshare-user", "--unshare-net", "--uid", "0", "--ro-bind", "/", "/", "true"])),
        "unprivileged user + network namespaces",
        "allow them, e.g. Ubuntu 24.04+: sysctl kernel.apparmor_restrict_unprivileged_userns=0 (or an AppArmor profile for bwrap); Debian: sysctl kernel.unprivileged_userns_clone=1",
    );
    check(rw("/dev/net/tun"), "read/write access to /dev/net/tun (analysis mode)", "load the tun module (modprobe tun)");
    if vm::uid_shift() {
        eprintln!("  ok    VMs run as a spare uid from /etc/subuid (rootless jail)");
    } else if std::env::var_os("AIRLOCK_NO_UIDSHIFT").is_some() {
        eprintln!("  warn  VMs run as your own uid (AIRLOCK_NO_UIDSHIFT is set: less isolation)");
    } else {
        check(
            false,
            "VMs run as a spare uid (required)",
            "give your user a range in /etc/subuid and /etc/subgid \
             (sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 $USER) and make sure \
             /dev/kvm and /dev/net/tun are mode 0666 (systemd's default)",
        );
    }
    // KVM in the host kernel is the wall around every VM: keep it patched.
    match host_kernel_age_days() {
        Some(d) if d > 120 => eprintln!(
            "  warn  your Linux kernel was built {d} days ago; the VM wall (KVM) is part of it\n        fix: install your distribution's kernel updates and reboot"
        ),
        Some(d) => eprintln!("  ok    Linux kernel is recent (built {d} days ago)"),
        None => {}
    }
    for (cmd, pkg) in [("ip", "iproute2"), ("nft", "nftables"), ("setpriv", "util-linux"), ("prlimit", "util-linux"), ("unshare", "util-linux"), ("mke2fs", "e2fsprogs")] {
        check(has(cmd), &format!("{cmd}"), &format!("install {pkg}"));
    }
    if has("xdg-dbus-proxy") {
        eprintln!("  ok    xdg-dbus-proxy (desktop app: web view runs in WebKit's sandbox)");
    } else {
        eprintln!("  warn  xdg-dbus-proxy missing: the desktop app's web view would run unsandboxed\n        fix: install xdg-dbus-proxy");
    }
    match vm::Assets::locate() {
        Ok(a) => {
            check(true, &format!("firecracker {}", a.firecracker.display()), "");
            let hardened = a.kernel.ends_with("vmlinux-airlock") || a.kernel.ends_with("lib/airlock/vmlinux");
            check(hardened, &format!("guest kernel {}", a.kernel.display()), "run guest/build-kernel.sh for the hardened kernel");
            check(true, &format!("guest image {}", a.rootfs.display()), "");
            image_age(&a.rootfs);
            check(true, &format!("sinkhole {}", a.sinkhole.display()), "");
        }
        Err(e) => check(false, &format!("build outputs ({e:#})"), "run scripts/bootstrap.sh"),
    }
    if failed > 0 {
        bail!("{failed} check(s) failed");
    }
    eprintln!("\nall checks passed — try: airlock selftest");
    Ok(())
}
