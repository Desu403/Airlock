//! The full analysis pipeline: detonate in a microVM wired to the sinkhole,
//! then examine the dead VM's disk in a second, fresh microVM.

use crate::{report, session, vm};
use anyhow::Result;

pub struct Analysis {
    pub report: report::Report,
    pub session: session::Session,
}

/// `progress` receives short human-readable status lines.
pub fn run(doc: &[u8], mode: &'static str, verbose: bool, progress: &dyn Fn(&str)) -> Result<Analysis> {
    let assets = vm::Assets::locate()?;
    let run = vm::RunDir::create(mode)?;
    let doc_disk = vm::write_doc_disk(&run.path, doc)?;
    let scratch = vm::make_scratch_disk(&run.path)?;
    let events = run.path.join("net.jsonl");

    progress("[1/2] detonating in a microVM wired to a fake internet...");
    let spec = vm::Spec {
        mode,
        drives: vec![
            vm::Drive { id: "doc", path: doc_disk, read_only: true },
            vm::Drive { id: "scratch", path: scratch.clone(), read_only: false },
        ],
        sinkhole_events: Some(events.clone()),
        options: &[],
    };
    let s = session::run(&assets, &run, &spec, verbose, verbose)?;
    progress(&format!("      VM destroyed after {:.1}s", s.elapsed.as_secs_f32()));

    // The dead VM's disk is examined by a *fresh* VM, never by the host.
    progress("[2/2] autopsy of the dead VM's disk in a second microVM...");
    let run2 = vm::RunDir::create("autopsy")?;
    // Hand the disk over: each VM's spare uid can only reach its own run dir.
    let evidence = run2.path.join("evidence.img");
    std::fs::rename(&scratch, &evidence)?;
    let spec2 = vm::Spec { mode: "autopsy", drives: vec![vm::Drive { id: "evidence", path: evidence, read_only: true }], sinkhole_events: None, options: &[] };
    let a = session::run(&assets, &run2, &spec2, verbose, false)?;

    let mut indicators = s.indicators.clone();
    if let Some(h) = &s.vm_hung {
        indicators.push((airlock_proto::Ind::RendererAbnormal, h.clone()));
    }
    indicators.extend(a.indicators);
    let mut report = report::Report::build(&indicators, Some(&events), &s.abnormal());
    if matches!(s.guest_error, Some(airlock_proto::Error::UnsupportedType)) {
        report.unreadable();
    }
    Ok(Analysis { report, session: s })
}
