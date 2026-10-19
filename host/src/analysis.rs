//! The full analysis pipeline: detonate in a microVM wired to the sinkhole,
//! then examine the dead VM's disk in a second, fresh microVM.

use crate::{report, session, vm};
use anyhow::Result;

pub struct Analysis {
    pub report: report::Report,
    pub session: session::Session,
    /// What happened, step by step (seconds since the start, plain words),
    /// for the app's analysis log: proof that each VM ran and was destroyed.
    pub log: Vec<(f32, String)>,
    /// ClamAV's VM has not finished yet (the early report of `run_staged`).
    pub clamav_pending: bool,
}

/// `progress` receives short human-readable status lines.
/// `name`: the file's name, for its extension (see vm::Spec::ext).
/// `entry`: analyze that file of an archive (unpacked inside the VM).
pub fn run(doc: &[u8], name: Option<&str>, entry: Option<u32>, mode: &'static str, verbose: bool, progress: &dyn Fn(&str)) -> Result<Analysis> {
    run_staged(doc, name, entry, mode, verbose, progress, &|_| {})
}

/// As `run`, with ClamAV in a VM of its own running alongside: `early`
/// receives the report from airlock's own checks as soon as they are done
/// (ClamAV still checking, `clamav_pending`), and the result includes
/// ClamAV's findings. ClamAV takes most of the time (loading ~8 million
/// signatures), so a verdict is shown long before it finishes.
pub fn run_staged(doc: &[u8], name: Option<&str>, entry: Option<u32>, mode: &'static str, verbose: bool, progress: &dyn Fn(&str), early: &dyn Fn(&Analysis)) -> Result<Analysis> {
    let t0 = std::time::Instant::now();
    let mut log: Vec<(f32, String)> = Vec::new();
    let mut note = |s: String| log.push((t0.elapsed().as_secs_f32(), s));
    let assets = vm::Assets::locate()?;
    // ClamAV's database (scripts/clamav-db.sh), when present: its VM starts
    // first and runs alongside the others.
    let sigs = assets.rootfs.parent().map(|p| p.join("clamav.ext4")).filter(|p| p.is_file() && std::env::var_os("AIRLOCK_NO_CLAMAV").is_none());
    let clam = sigs.map(|sigs| {
        let (doc, ext) = (doc.to_vec(), name.and_then(vm::ext_hint));
        std::thread::spawn(move || -> Result<session::Session> {
            let assets = vm::Assets::locate()?;
            let run = vm::RunDir::create("clamav")?;
            let disk = vm::write_doc_disk(&run.path, &doc)?;
            let spec = vm::Spec { mode: "clamav", drives: vec![vm::Drive { id: "doc", path: disk, read_only: true }, vm::Drive { id: "sigs", path: sigs, read_only: true }], sinkhole_events: None, options: &[], ext, entry };
            session::run(&assets, &run, &spec, verbose, false)
        })
    });
    if clam.is_some() {
        note("ClamAV VM started alongside: it scans the file with Cisco Talos's signatures, with no network".into());
    }
    let run = vm::RunDir::create(mode)?;
    let doc_disk = vm::write_doc_disk(&run.path, doc)?;
    let scratch = vm::make_scratch_disk(&run.path)?;
    let events = run.path.join("net.jsonl");

    progress("[1/2] detonating in a microVM wired to a fake internet...");
    note(format!("Analysis VM 1 started: the document is opened by its own program, cut off from your computer; its only network is a fake internet ({} KB document)", doc.len().div_ceil(1024)));
    let spec = vm::Spec {
        mode,
        drives: vec![vm::Drive { id: "doc", path: doc_disk, read_only: true }, vm::Drive { id: "scratch", path: scratch.clone(), read_only: false }],
        sinkhole_events: Some(events.clone()),
        options: &[],
        ext: name.and_then(vm::ext_hint),
        entry,
    };
    let s = session::run(&assets, &run, &spec, verbose, verbose)?;
    progress(&format!("      VM destroyed after {:.1}s", s.elapsed.as_secs_f32()));
    note(format!("VM 1 finished and was destroyed after {:.1} s: {} observation(s) recorded", s.elapsed.as_secs_f32(), s.indicators.len()));
    if let Some(e) = &s.guest_error {
        note(format!("VM 1 reported: {e:?}"));
    }
    if let Some(p) = &s.protocol_violation {
        note(format!("VM 1 broke airlock's rules ({p}) and was killed at once"));
    }
    if let Some(d) = &s.vm_died {
        note(format!("VM 1 crashed on its own: {d}"));
    }
    if let Some(h) = &s.vm_hung {
        note(format!("VM 1 stopped answering and was destroyed: {h}"));
    }
    let net = std::fs::read_to_string(&events).map(|t| t.lines().filter(|l| !l.trim().is_empty()).count()).unwrap_or(0);
    note(format!("Fake internet: {net} connection attempt(s) caught; nothing reached the real network"));

    // The dead VM's disk is examined by a *fresh* VM, never by the host.
    progress("[2/2] autopsy of the dead VM's disk in a second microVM...");
    let run2 = vm::RunDir::create("autopsy")?;
    // Hand the disk over: each VM's spare uid can only reach its own run dir.
    let evidence = run2.path.join("evidence.img");
    std::fs::rename(&scratch, &evidence)?;
    let spec2 = vm::Spec { mode: "autopsy", drives: vec![vm::Drive { id: "evidence", path: evidence, read_only: true }], sinkhole_events: None, options: &[], ext: None, entry: None };
    note("Autopsy VM 2 started: a fresh VM examines VM 1's leftover disk (your computer never reads it)".into());
    let a = session::run(&assets, &run2, &spec2, verbose, false)?;
    note(format!("VM 2 finished and was destroyed after {:.1} s: {} observation(s) recorded", a.elapsed.as_secs_f32(), a.indicators.len()));
    if let Some(d) = &a.vm_died {
        note(format!("VM 2 crashed: {d}"));
    }

    let mut indicators = s.indicators.clone();
    if let Some(h) = &s.vm_hung {
        indicators.push((airlock_proto::Ind::RendererAbnormal, h.clone()));
    }
    indicators.extend(a.indicators);
    let abnormal = s.abnormal();
    let unreadable = matches!(s.guest_error, Some(airlock_proto::Error::UnsupportedType));
    let build = |indicators: &[(airlock_proto::Ind, String)], log: &mut Vec<(f32, String)>| {
        let mut report = report::Report::build(indicators, Some(&events), &abnormal);
        if unreadable {
            report.unreadable();
        }
        // Every web address the document carries, against URLhaus's list.
        let texts: Vec<&str> = indicators.iter().map(|(_, t)| t.as_str()).filter(|t| t.contains("http")).collect();
        let bad = crate::known::malware_urls(&texts);
        if !bad.is_empty() {
            report.malware_sites(&bad);
            log.push((t0.elapsed().as_secs_f32(), format!("{} link(s) found in the local list of active malware addresses (URLhaus)", bad.len())));
        }
        if let Some((sha, n)) = crate::known::lookup(doc) {
            report.known_malware(&sha, n);
            log.push((t0.elapsed().as_secs_f32(), format!("Fingerprint found in the local list of {n} known-malware fingerprints (MalwareBazaar)")));
        }
        report
    };
    let Some(clam) = clam else {
        let report = build(&indicators, &mut log);
        log.push((t0.elapsed().as_secs_f32(), format!("Report built from {} observation(s). Both VMs and their disks are gone; your computer only received the findings", indicators.len())));
        return Ok(Analysis { report, session: s, log, clamav_pending: false });
    };

    // airlock's own checks are done: a first report while ClamAV finishes.
    let mut first_log = log.clone();
    let report = build(&indicators, &mut first_log);
    first_log.push((t0.elapsed().as_secs_f32(), format!("airlock's own checks are done ({} observation(s)); ClamAV is still checking", indicators.len())));
    early(&Analysis { report, session: session::Session { indicators: s.indicators.clone(), ..Default::default() }, log: first_log, clamav_pending: true });
    progress("      ClamAV still checking...");

    match clam.join().map_err(|_| anyhow::anyhow!("ClamAV thread panicked")).and_then(|r| r) {
        Ok(c) => {
            note_at(&mut log, t0, format!("ClamAV VM finished and was destroyed after {:.1} s: {} finding(s)", c.elapsed.as_secs_f32(), c.indicators.len()));
            if let Some(v) = &c.protocol_violation {
                note_at(&mut log, t0, format!("ClamAV VM broke airlock's rules ({v}) and was killed at once"));
            }
            indicators.extend(c.indicators);
        }
        Err(e) => note_at(&mut log, t0, format!("ClamAV could not run ({e:#}); the other checks are complete")),
    }
    let report = build(&indicators, &mut log);
    note_at(&mut log, t0, format!("Report built from {} observation(s). All VMs and their disks are gone; your computer only received the findings", indicators.len()));
    Ok(Analysis { report, session: s, log, clamav_pending: false })
}

fn note_at(log: &mut Vec<(f32, String)>, t0: std::time::Instant, s: String) {
    log.push((t0.elapsed().as_secs_f32(), s));
}
