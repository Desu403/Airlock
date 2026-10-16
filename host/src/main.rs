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
    let (mut input, mut out_dir, mut verbose) = (None, None, false);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--out" => out_dir = Some(PathBuf::from(args.next().unwrap_or_else(|| usage()))),
            "--verbose" | "-v" => verbose = true,
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
                analyze(&doc, &out, verbose, "analyze").map(|_| ())
            }
        }
        "doctor" => doctor(),
        "livecheck" => livecheck(&read_doc(&input.unwrap_or_else(|| usage()))?),
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

fn analyze(doc: &[u8], out_dir: &Path, verbose: bool, mode: &'static str) -> Result<report::Report> {
    let a = analysis::run(doc, mode, verbose, &|line| eprintln!("airlock: {line}"))?;
    let (rep, s) = (a.report, a.session);
    rep.print();
    std::fs::create_dir_all(out_dir)?;
    std::fs::write(out_dir.join("report.json"), serde_json::to_vec_pretty(&rep.to_json())?)?;
    if s.protocol_violation.is_none() {
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
    let rep = analyze(&blank, &out_dir, verbose, "selftest")?;
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
    let mut s = live::LiveSession::open(doc)?;
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

/// Checks everything airlock needs on this machine, with a fix for each miss.
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
    } else {
        eprintln!(
            "  warn  VMs run as your own uid (no spare-uid isolation)\n        fix: give your user a range in /etc/subuid and /etc/subgid \
             (sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 $USER) and make sure \
             /dev/kvm and /dev/net/tun are mode 0666 (systemd's default)"
        );
    }
    for (cmd, pkg) in [("ip", "iproute2"), ("nft", "nftables"), ("setpriv", "util-linux"), ("mke2fs", "e2fsprogs")] {
        check(has(cmd), &format!("{cmd}"), &format!("install {pkg}"));
    }
    match vm::Assets::locate() {
        Ok(a) => {
            check(true, &format!("firecracker {}", a.firecracker.display()), "");
            let hardened = a.kernel.ends_with("vmlinux-airlock");
            check(hardened, &format!("guest kernel {}", a.kernel.display()), "run guest/build-kernel.sh for the hardened kernel");
            check(true, &format!("guest image {}", a.rootfs.display()), "");
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
