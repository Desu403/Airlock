//! A live viewing session: the document stays inside a running microVM
//! (no network device) and the host asks for what it needs. Everything that
//! comes back is validated here; page text is re-sanitised (`text`) before
//! any UI sees it.

use crate::{pdf, text, vm};
use airlock_proto::{valid_text, Cmd, Error, Header, Ind, Kind, HEADER_LEN, MAX_DPI, MAX_QUERY, MIN_DPI};
use anyhow::{anyhow, bail, Context, Result};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

const BOOT_TIMEOUT: Duration = Duration::from_secs(150);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
/// Start of the error when the document's VM is no longer running.
pub const VM_STOPPED: &str = "the document's VM stopped";
/// Start of the error when the tripwire fired (see `is_attack`).
pub const TRIPWIRE: &str = "the document attacked its VM";

/// What a viewing VM never does on its own: start programs, use the
/// network, touch other processes, reach risky kernel interfaces. The
/// monitor blocks each one; the first one also ends the session (the
/// tripwire), so an exploit gets no second try.
pub fn is_attack(i: Ind) -> bool {
    matches!(i, Ind::Exec | Ind::ProcessCreate | Ind::Socket | Ind::Connect | Ind::KernelSurface | Ind::Ptrace)
}

/// How spreadsheets are laid out (other documents keep their own pages).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Layout {
    /// Fitted to the page width, as many pages down as needed.
    Pages,
    /// Each sheet on one page sized to its content, when that stays readable.
    OnePagePerSheet,
}

impl Layout {
    fn options(self) -> &'static [&'static str] {
        match self {
            Layout::Pages => &[],
            Layout::OnePagePerSheet => &["airlock.sheets=single"],
        }
    }
}

/// Whether `doc` is a spreadsheet (content sniffing, as the guest does).
pub fn is_spreadsheet(doc: &[u8]) -> bool {
    let has = |n: &[u8]| doc.windows(n.len()).any(|w| w == n);
    let utf16 = |s: &str| s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect::<Vec<u8>>();
    if doc.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]) {
        return !has(&utf16("WordDocument")) && (has(&utf16("Workbook")) || has(&utf16("Book")));
    }
    if doc.starts_with(b"PK\x03\x04") {
        let head = &doc[..doc.len().min(256)];
        return (!has(b"word/") && has(b"xl/")) || head.windows(54).any(|w| w == b"mimetypeapplication/vnd.oasis.opendocument.spreadsheet");
    }
    false
}

pub struct PageSize {
    /// Points.
    pub width: f32,
    pub height: f32,
}

pub struct Hit {
    pub page: u32,
    /// x0, y0, x1, y1 in points, top-left origin.
    pub rect: [f32; 4],
}

/// One line of page text and where it sits, for a selectable text layer.
pub struct Line {
    /// x0, y0, x1, y1 in points, top-left origin.
    pub rect: [f32; 4],
    pub text: String,
}

enum Msg {
    Hello(u32),
    PageInfo(u32, PageSize),
    Page(u32, pdf::Page),
    Hits(u32, Vec<[f32; 4]>),
    Lines(u32, Vec<[f32; 4]>),
    SearchDone,
    Text(u32, String),
    Done,
}

pub struct LiveSession {
    run: vm::RunDir,
    child: std::process::Child,
    stream: UnixStream,
    pub pages: Vec<PageSize>,
    /// Anything the in-VM monitor reported while we were viewing.
    pub indicators: Vec<(Ind, String)>,
    pub boot_time: Duration,
}

impl LiveSession {
    /// Boots a live VM for `doc` (PDF or Office). The VM has no network device.
    pub fn open(doc: &[u8]) -> Result<Self> {
        Self::open_with(doc, Layout::Pages)
    }

    pub fn open_with(doc: &[u8], layout: Layout) -> Result<Self> {
        let started = Instant::now();
        let assets = vm::Assets::locate()?;
        let run = vm::RunDir::create("live")?;
        let doc_disk = vm::write_doc_disk(&run.path, doc)?;
        let listener = run.listen()?;
        let spec = vm::Spec { mode: "live", drives: vec![vm::Drive { id: "doc", path: doc_disk, read_only: true }], sinkhole_events: None, options: layout.options() };
        let mut child = vm::spawn(&assets, &run, &spec, &run.path.join("console.log"))?;

        let deadline = Instant::now() + BOOT_TIMEOUT;
        let stream = loop {
            match listener.accept() {
                Ok((s, _)) => break s,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e.into()),
            }
            if child.try_wait()?.is_some() || Instant::now() > deadline {
                let _ = child.kill();
                bail!("microVM failed to start");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        stream.set_nonblocking(false)?;
        // Opening includes Office conversion, which can take a while.
        stream.set_read_timeout(Some(BOOT_TIMEOUT))?;
        let mut s = LiveSession { run, child, stream, pages: Vec::new(), indicators: Vec::new(), boot_time: Duration::ZERO };

        let count = match s.next()? {
            Msg::Hello(n) => n,
            _ => return Err(s.hostile("expected hello")),
        };
        for i in 0..count {
            match s.next()? {
                Msg::PageInfo(p, size) if p == i => s.pages.push(size),
                _ => return Err(s.hostile("expected page info")),
            }
        }
        s.stream.set_read_timeout(Some(REQUEST_TIMEOUT))?;
        s.boot_time = started.elapsed();
        Ok(s)
    }

    fn hostile(&mut self, what: &str) -> anyhow::Error {
        let _ = self.child.kill();
        anyhow!("protocol violation: {what} — VM killed, guest treated as hostile")
    }

    /// Whether the VM is still running.
    pub fn alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// An I/O error on the stream: if the VM is gone, say so and why (exit
    /// status and the last lines of its console), for the log. A VM that is
    /// still running but did not answer in time (hung, or busy attacking) is
    /// destroyed: fail closed, and no late reply can be mistaken for the next.
    fn io_error(&mut self, e: anyhow::Error) -> anyhow::Error {
        std::thread::sleep(Duration::from_millis(50));
        match self.child.try_wait() {
            Ok(Some(status)) => {
                let console = std::fs::read_to_string(self.run.path.join("console.log")).unwrap_or_default();
                let tail: Vec<&str> = console.lines().rev().take(3).collect();
                anyhow!("{VM_STOPPED} ({status}; last console lines: {})", tail.into_iter().rev().collect::<Vec<_>>().join(" | "))
            }
            _ => {
                let _ = self.child.kill();
                let _ = self.child.wait();
                anyhow!("{VM_STOPPED} (it stopped responding and was destroyed: {e:#})")
            }
        }
    }

    /// How long one request may take before the VM is destroyed.
    pub fn set_request_timeout(&mut self, t: Duration) -> Result<()> {
        Ok(self.stream.set_read_timeout(Some(t))?)
    }

    /// Process ids of the VM and its jail (for the containment test).
    pub fn jail_pids(&self) -> Vec<u32> {
        let mut pids = vec![self.child.id()];
        let mut i = 0;
        while i < pids.len() && pids.len() < 256 {
            let parent = pids[i];
            if let Ok(rd) = std::fs::read_dir("/proc") {
                for e in rd.flatten() {
                    let Some(pid) = e.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else { continue };
                    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
                    // Fields after the parenthesised name: state, ppid, ...
                    let ppid = stat.rsplit_once(')').and_then(|(_, r)| r.split_whitespace().nth(1)).and_then(|p| p.parse::<u32>().ok());
                    if ppid == Some(parent) && !pids.contains(&pid) {
                        pids.push(pid);
                    }
                }
            }
            i += 1;
        }
        pids
    }

    fn send(&mut self, cmd: Cmd, a: u32, b: u32, payload: &[u8]) -> Result<()> {
        let h = Header { kind: cmd as u32, a, b, c: 0, len: payload.len() as u32 };
        let r = self.stream.write_all(&h.encode()).and_then(|_| self.stream.write_all(payload));
        r.map_err(|e| self.io_error(e.into()))
    }

    /// Reads one message; indicators are collected on the side.
    fn next(&mut self) -> Result<Msg> {
        match read_msg(&mut self.stream, &mut self.indicators) {
            Ok(m) => Ok(m),
            Err(Bad::Hostile(what)) => Err(self.hostile(what)),
            Err(Bad::Tripwire(what)) => {
                let _ = self.child.kill();
                Err(anyhow!("{TRIPWIRE}: {what} (blocked; the VM was destroyed at once)"))
            }
            Err(Bad::Other(e)) => Err(self.io_error(e)),
        }
    }

    pub fn render(&mut self, page: u32, dpi: u32) -> Result<pdf::Page> {
        if page as usize >= self.pages.len() {
            bail!("no page {page}");
        }
        self.send(Cmd::Render, page, dpi.clamp(MIN_DPI, MAX_DPI), &[])?;
        match self.next()? {
            Msg::Page(p, img) if p == page => Ok(img),
            _ => Err(self.hostile("expected the requested page")),
        }
    }

    pub fn search(&mut self, query: &str) -> Result<Vec<Hit>> {
        let mut q = query.trim().as_bytes().to_vec();
        if q.is_empty() {
            return Ok(Vec::new());
        }
        q.truncate(MAX_QUERY as usize);
        let q = String::from_utf8_lossy(&q).trim_end_matches('\u{FFFD}').as_bytes().to_vec();
        self.send(Cmd::Search, 0, 0, &q)?;
        let mut hits = Vec::new();
        loop {
            match self.next()? {
                Msg::Hits(p, rects) if (p as usize) < self.pages.len() && hits.len() < 5000 => {
                    hits.extend(rects.into_iter().map(|rect| Hit { page: p, rect }))
                }
                Msg::SearchDone => return Ok(hits),
                _ => return Err(self.hostile("unexpected search reply")),
            }
        }
    }

    pub fn text(&mut self, page: u32) -> Result<String> {
        if page as usize >= self.pages.len() {
            bail!("no page {page}");
        }
        self.send(Cmd::GetText, page, 0, &[])?;
        match self.next()? {
            Msg::Text(p, t) if p == page => Ok(t),
            _ => Err(self.hostile("expected page text")),
        }
    }

    /// Character counts for the AI-text hints (numbers only, see Cmd::TextStats).
    pub fn text_stats(&mut self, page: u32) -> Result<std::collections::BTreeMap<String, u64>> {
        if page as usize >= self.pages.len() {
            bail!("no page {page}");
        }
        self.send(Cmd::TextStats, page, 0, &[])?;
        let raw = match self.next()? {
            Msg::Text(p, t) if p == page => t,
            _ => return Err(self.hostile("expected text statistics")),
        };
        let mut out = std::collections::BTreeMap::new();
        for pair in raw.split_whitespace().take(32) {
            let Some((k, v)) = pair.split_once('=') else { return Err(self.hostile("malformed text statistics")) };
            let Ok(v) = v.parse::<u64>() else { return Err(self.hostile("malformed text statistics")) };
            if k.len() > 16 || !k.bytes().all(|b| b.is_ascii_lowercase()) {
                return Err(self.hostile("malformed text statistics"));
            }
            out.insert(k.to_string(), v);
        }
        Ok(out)
    }

    /// Lines of text with their boxes. Text is sanitised like `text`; a box
    /// that is degenerate or off the page is dropped with its line.
    pub fn lines(&mut self, page: u32) -> Result<Vec<Line>> {
        let Some(size) = self.pages.get(page as usize) else { bail!("no page {page}") };
        let (pw, ph) = (size.width, size.height);
        self.send(Cmd::GetLayout, page, 0, &[])?;
        let boxes = match self.next()? {
            Msg::Lines(p, b) if p == page => b,
            _ => return Err(self.hostile("expected line boxes")),
        };
        let text = match self.next()? {
            Msg::Text(p, t) if p == page => t,
            _ => return Err(self.hostile("expected page text")),
        };
        Ok(boxes
            .into_iter()
            .zip(text.split('\n'))
            .filter(|(r, _)| r[0] < r[2] && r[1] < r[3] && r[2] <= pw + 1.0 && r[3] <= ph + 1.0)
            .map(|(rect, t)| Line { rect, text: t.to_owned() })
            .collect())
    }

    pub fn close(mut self) {
        let _ = self.send(Cmd::Quit, 0, 0, &[]);
        let _ = self.stream.set_read_timeout(Some(Duration::from_millis(500)));
        let deadline = Instant::now() + Duration::from_secs(2);
        while self.child.try_wait().ok().flatten().is_none() && Instant::now() < deadline {
            let _ = self.next();
        }
    }
}

impl Drop for LiveSession {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

enum Bad {
    /// The guest broke the protocol: kill it.
    Hostile(&'static str),
    /// The monitor blocked an attack attempt: kill it.
    Tripwire(String),
    /// I/O failure, or the guest reported an error.
    Other(anyhow::Error),
}

/// Parses one message from the untrusted guest stream. Every length comes
/// from a header that `Header::decode` already bounded.
fn read_msg(r: &mut impl Read, indicators: &mut Vec<(Ind, String)>) -> std::result::Result<Msg, Bad> {
    loop {
        let mut buf = [0u8; HEADER_LEN];
        r.read_exact(&mut buf).context("VM stopped responding").map_err(Bad::Other)?;
        let Some(h) = Header::decode(&buf) else { return Err(Bad::Hostile("malformed header")) };
        let mut payload = vec![0u8; h.len as usize];
        r.read_exact(&mut payload).context("truncated message").map_err(Bad::Other)?;
        let msg = match h.kind {
            k if k == Kind::Indicator as u32 => {
                if !valid_text(&payload) || indicators.len() >= 1000 {
                    return Err(Bad::Hostile("bad indicator"));
                }
                let (ind, text) = (Ind::from_u32(h.a).unwrap(), String::from_utf8(payload).unwrap());
                indicators.push((ind, text.clone()));
                if is_attack(ind) {
                    return Err(Bad::Tripwire(text));
                }
                continue;
            }
            k if k == Kind::Hello as u32 => Msg::Hello(h.a),
            k if k == Kind::PageInfo as u32 => Msg::PageInfo(h.a, PageSize { width: h.b as f32 / 10.0, height: h.c as f32 / 10.0 }),
            k if k == Kind::Page as u32 => {
                let rgb = payload.chunks_exact(4).flat_map(|p| {
                    let a = p[3] as u32;
                    [0, 1, 2].map(|i| ((p[i] as u32 * a + 255 * (255 - a)) / 255) as u8)
                });
                Msg::Page(h.a, pdf::Page { width: h.b, height: h.c, rgb: rgb.collect() })
            }
            k if k == Kind::SearchHits as u32 => Msg::Hits(h.a, rects(&payload)),
            k if k == Kind::PageLines as u32 => Msg::Lines(h.a, rects(&payload)),
            k if k == Kind::SearchDone as u32 => Msg::SearchDone,
            k if k == Kind::PageText as u32 => Msg::Text(h.a, text::sanitize(&payload)),
            k if k == Kind::Done as u32 => Msg::Done,
            k if k == Kind::Error as u32 => return Err(Bad::Other(anyhow!("VM reported {:?}", Error::from_u32(h.a).unwrap()))),
            _ => return Err(Bad::Hostile("unexpected message")),
        };
        return Ok(msg);
    }
}

/// n * 16 bytes of u32 LE tenths of a point -> rectangles in points.
fn rects(payload: &[u8]) -> Vec<[f32; 4]> {
    payload
        .chunks_exact(16)
        .map(|r| {
            let v = |i: usize| u32::from_le_bytes(r[i * 4..i * 4 + 4].try_into().unwrap()) as f32 / 10.0;
            [v(0), v(1), v(2), v(3)]
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fuzz::{hostile_stream, iters, Rng};
    use airlock_proto::{MAX_DIM, MAX_LINES, MAX_PAGES, MAX_PAGE_TEXT, MAX_RECTS};

    #[test]
    fn fuzz_read_msg() {
        let mut rng = Rng::from_env("fuzz_read_msg");
        for _ in 0..iters(50_000) {
            let data = hostile_stream(&mut rng);
            let mut r = &data[..];
            let mut inds = Vec::new();
            while let Ok(m) = read_msg(&mut r, &mut inds) {
                match m {
                    Msg::Page(p, img) => {
                        assert!(p < MAX_PAGES);
                        assert!((1..=MAX_DIM).contains(&img.width) && (1..=MAX_DIM).contains(&img.height));
                        assert_eq!(img.rgb.len(), (img.width * img.height * 3) as usize);
                    }
                    Msg::Hits(p, rects) => assert!(p < MAX_PAGES && !rects.is_empty() && rects.len() <= MAX_RECTS as usize),
                    Msg::Lines(p, rects) => assert!(p < MAX_PAGES && rects.len() <= MAX_LINES as usize),
                    // Lossy UTF-8 can triple invalid bytes; sanitising only removes.
                    Msg::Text(p, t) => assert!(p < MAX_PAGES && t.len() <= MAX_PAGE_TEXT as usize * 3),
                    Msg::PageInfo(p, size) => assert!(p < MAX_PAGES && size.width > 0.0 && size.height > 0.0 && size.width <= 100_000.0),
                    Msg::Hello(_) | Msg::SearchDone | Msg::Done => {}
                }
            }
            assert!(inds.len() <= 1000 && inds.iter().all(|(_, t)| valid_text(t.as_bytes())));
        }
    }
}
