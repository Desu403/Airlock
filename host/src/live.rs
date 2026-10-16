//! A live viewing session: the document stays inside a running microVM
//! (no network device) and the host asks for what it needs. Everything that
//! comes back is validated here; page text is re-sanitised before any UI
//! sees it.

use crate::{pdf, vm};
use airlock_proto::{valid_text, Cmd, Error, Header, Ind, Kind, HEADER_LEN, MAX_DPI, MAX_QUERY, MIN_DPI};
use anyhow::{anyhow, bail, Context, Result};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

const BOOT_TIMEOUT: Duration = Duration::from_secs(150);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

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
    _run: vm::RunDir,
    child: std::process::Child,
    stream: UnixStream,
    pub pages: Vec<PageSize>,
    /// Anything the in-VM monitor reported while we were viewing.
    pub indicators: Vec<(Ind, String)>,
    pub boot_time: Duration,
}

/// Page text is attacker-controlled. Keep printable text and line breaks;
/// drop control characters and bidi overrides ("Trojan Source").
pub fn sanitize_text(raw: &[u8]) -> String {
    String::from_utf8_lossy(raw)
        .chars()
        .filter(|&c| {
            c == '\n'
                || c == '\t'
                || !(c.is_control()
                    || matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}' | '\u{061C}' | '\u{FEFF}'))
        })
        .collect()
}

impl LiveSession {
    /// Boots a live VM for `doc` (PDF or Office). The VM has no network device.
    pub fn open(doc: &[u8]) -> Result<Self> {
        let started = Instant::now();
        let assets = vm::Assets::locate()?;
        let run = vm::RunDir::create("live")?;
        let doc_disk = vm::write_doc_disk(&run.path, doc)?;
        let listener = run.listen()?;
        let spec = vm::Spec { mode: "live", drives: vec![vm::Drive { id: "doc", path: doc_disk, read_only: true }], sinkhole_events: None };
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
        let mut s = LiveSession { _run: run, child, stream, pages: Vec::new(), indicators: Vec::new(), boot_time: Duration::ZERO };

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

    fn send(&mut self, cmd: Cmd, a: u32, b: u32, payload: &[u8]) -> Result<()> {
        let h = Header { kind: cmd as u32, a, b, c: 0, len: payload.len() as u32 };
        self.stream.write_all(&h.encode())?;
        self.stream.write_all(payload)?;
        Ok(())
    }

    /// Reads one message; indicators are collected on the side.
    fn next(&mut self) -> Result<Msg> {
        loop {
            let mut buf = [0u8; HEADER_LEN];
            self.stream.read_exact(&mut buf).context("VM stopped responding")?;
            let Some(h) = Header::decode(&buf) else { return Err(self.hostile("malformed header")) };
            let mut payload = vec![0u8; h.len as usize];
            self.stream.read_exact(&mut payload).context("truncated message")?;
            let msg = match h.kind {
                k if k == Kind::Indicator as u32 => {
                    if !valid_text(&payload) || self.indicators.len() >= 1000 {
                        return Err(self.hostile("bad indicator"));
                    }
                    self.indicators.push((Ind::from_u32(h.a).unwrap(), String::from_utf8(payload).unwrap()));
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
                k if k == Kind::PageText as u32 => Msg::Text(h.a, sanitize_text(&payload)),
                k if k == Kind::Done as u32 => Msg::Done,
                k if k == Kind::Error as u32 => bail!("VM reported {:?}", Error::from_u32(h.a).unwrap()),
                _ => return Err(self.hostile("unexpected message")),
            };
            return Ok(msg);
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
    use super::sanitize_text;

    #[test]
    fn strips_trojan_source_and_controls() {
        let evil = "pay\u{202E}fdp.exe\u{1b}[2J\u{7}ok\nline2\u{2066}x";
        assert_eq!(sanitize_text(evil.as_bytes()), "payfdp.exe[2Jok\nline2x");
        assert_eq!(sanitize_text(b"\xff\xfeA"), "\u{FFFD}\u{FFFD}A");
    }
}
