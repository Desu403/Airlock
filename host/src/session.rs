//! Runs one VM and reads its stream through a strict state machine. Any
//! deviation from the protocol is treated as a hostile guest.

use crate::{pdf, vm};
use airlock_proto::{valid_text, Error, Header, Ind, Kind, HEADER_LEN};
use anyhow::{bail, Context, Result};
use std::io::Read;
use std::os::unix::net::{UnixListener, UnixStream};
use std::time::{Duration, Instant};

const BOOT_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(90);

#[derive(Default)]
pub struct Session {
    pub pages: Vec<pdf::Page>,
    pub indicators: Vec<(Ind, String)>,
    pub guest_error: Option<Error>,
    pub protocol_violation: Option<String>,
    /// The VM died on its own mid-session (e.g. guest kernel panic: the
    /// hardened kernel panics on any oops, a typical exploit side effect).
    pub vm_died: Option<String>,
    pub elapsed: Duration,
}

impl Session {
    /// Outside observations about the VM itself, for the report.
    pub fn abnormal(&self) -> Vec<String> {
        let mut v = Vec::new();
        if let Some(p) = &self.protocol_violation {
            v.push(format!("guest broke the protocol ({p}) — VM was killed"));
        }
        v.extend(self.vm_died.clone());
        v
    }
}

pub fn run(assets: &vm::Assets, run: &vm::RunDir, spec: &vm::Spec, verbose: bool, progress: bool) -> Result<Session> {
    let listener = run.listen()?;
    let log = run.path.join("console.log");
    let started = Instant::now();
    let mut child = vm::spawn(assets, run, spec, &log)?;

    let mut session = Session::default();
    let stream = accept(&listener, &mut child);
    let connected = stream.is_ok();
    let result = stream.and_then(|s| receive(s, &mut session, progress));
    if let Err(e) = &result {
        if format!("{e:#}").starts_with("protocol violation") {
            session.protocol_violation = Some(format!("{e:#}"));
        }
    }

    // A VM that never connected failed to start: that is an error, not a finding.
    if connected && result.is_err() && session.protocol_violation.is_none() {
        // Did the VM die by itself while we were talking to it?
        std::thread::sleep(Duration::from_millis(200));
        if child.try_wait()?.is_some() {
            let console = vm::sanitized_log(&log);
            session.vm_died = Some(if console.contains("Kernel panic") {
                "the guest kernel panicked mid-session (typical side effect of a kernel exploit attempt)".into()
            } else {
                "the VM died unexpectedly mid-session".into()
            });
        }
    }

    // Give the guest a moment to power off cleanly; whatever happened, the VM dies now.
    let grace = Instant::now() + Duration::from_secs(3);
    while result.is_ok() && child.try_wait()?.is_none() && Instant::now() < grace {
        std::thread::sleep(Duration::from_millis(10));
    }
    let _ = child.kill();
    let _ = child.wait();
    session.elapsed = started.elapsed();
    if verbose {
        eprintln!("--- {} VM: kernel {} ---", spec.mode, assets.kernel.display());
        eprintln!("--- {} VM console (sanitized) ---\n{}--- end ---", spec.mode, vm::sanitized_log(&log));
    }
    match result {
        Ok(()) => Ok(session),
        Err(_) if session.protocol_violation.is_some() || session.vm_died.is_some() => Ok(session),
        Err(e) => Err(e),
    }
}

fn accept(listener: &UnixListener, child: &mut std::process::Child) -> Result<UnixStream> {
    let deadline = Instant::now() + BOOT_TIMEOUT;
    loop {
        match listener.accept() {
            Ok((s, _)) => {
                s.set_nonblocking(false)?;
                s.set_read_timeout(Some(IO_TIMEOUT))?;
                return Ok(s);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e.into()),
        }
        if let Some(st) = child.try_wait()? {
            bail!("microVM exited before connecting ({st}); re-run with --verbose");
        }
        if Instant::now() > deadline {
            bail!("microVM did not connect within {BOOT_TIMEOUT:?}");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn receive(mut s: impl Read, out: &mut Session, progress: bool) -> Result<()> {
    let mut count: Option<u32> = None;
    loop {
        let mut buf = [0u8; HEADER_LEN];
        s.read_exact(&mut buf).context("guest stream ended early")?;
        let h = Header::decode(&buf).context("protocol violation: malformed header")?;
        match h.kind {
            k if k == Kind::Indicator as u32 => {
                let mut text = vec![0u8; h.len as usize];
                s.read_exact(&mut text).context("truncated indicator")?;
                if !valid_text(&text) {
                    bail!("protocol violation: non-printable indicator text");
                }
                if out.indicators.len() >= 1000 {
                    bail!("protocol violation: indicator flood");
                }
                // valid_text guarantees ASCII.
                out.indicators.push((Ind::from_u32(h.a).unwrap(), String::from_utf8(text).unwrap()));
            }
            k if k == Kind::Hello as u32 => {
                if count.is_some() {
                    bail!("protocol violation: second hello");
                }
                count = Some(h.a);
            }
            k if k == Kind::Page as u32 => {
                let Some(total) = count else { bail!("protocol violation: page before hello") };
                if h.a as usize != out.pages.len() || h.a >= total {
                    bail!("protocol violation: page out of order");
                }
                let mut rgba = vec![0u8; h.len as usize];
                s.read_exact(&mut rgba).context("truncated page")?;
                // Composite onto white and drop alpha: the output is plain RGB.
                let rgb = rgba
                    .chunks_exact(4)
                    .flat_map(|p| {
                        let a = p[3] as u32;
                        [0, 1, 2].map(|i| ((p[i] as u32 * a + 255 * (255 - a)) / 255) as u8)
                    })
                    .collect();
                out.pages.push(pdf::Page { width: h.b, height: h.c, rgb });
                if progress {
                    eprint!("\rairlock: received page {}/{total}", out.pages.len());
                }
            }
            k if k == Kind::Done as u32 => {
                if progress && !out.pages.is_empty() {
                    eprintln!();
                }
                if h.a != count.unwrap_or(0) || out.pages.len() != h.a as usize {
                    bail!("protocol violation: page count mismatch");
                }
                return Ok(());
            }
            k if k == Kind::Error as u32 => {
                if progress && !out.pages.is_empty() {
                    eprintln!();
                }
                out.guest_error = Error::from_u32(h.a);
                return Ok(());
            }
            _ => bail!("protocol violation: unexpected message"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fuzz::{hostile_stream, iters, Rng};

    #[test]
    fn fuzz_receive() {
        let mut rng = Rng::from_env("fuzz_receive");
        for _ in 0..iters(50_000) {
            let data = hostile_stream(&mut rng);
            let mut s = Session::default();
            let ok = receive(&data[..], &mut s, false).is_ok();
            assert!(s.indicators.len() <= 1000 && s.indicators.iter().all(|(_, t)| valid_text(t.as_bytes())));
            for p in &s.pages {
                assert_eq!(p.rgb.len(), (p.width * p.height * 3) as usize);
            }
            if ok && s.guest_error.is_none() {
                assert!(!s.pages.is_empty() || data.len() >= HEADER_LEN, "Done without a stream");
            }
        }
    }
}
