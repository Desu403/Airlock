//! Live viewing: the VM stays up and answers host requests until told to quit.
//! Only pixels, numbers (page sizes, search and line rectangles) and page
//! text leave.

use crate::monitor::{self, Net, Opts};
use crate::{fail, finish, pam_to_rgba, send, send_indicators};
use airlock_proto::{Cmd, Error, Header, Kind, HEADER_LEN, MAX_DIM, MAX_LINES, MAX_PAGES, MAX_PAGE_TEXT, MAX_RECTS};
use std::fs::File;
use std::io::Read;
use std::time::Duration;

const WORK: &str = "/tmp/work";

struct Page {
    w: f32,
    h: f32,
    /// '\n' entries mark line ends and carry an empty box.
    chars: Vec<(char, [f32; 4])>,
}

fn attr<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let key = format!(" {name}=\"");
    let start = line.find(&key)? + key.len();
    let end = line[start..].find('"')? + start;
    Some(&line[start..end])
}

fn unescape(s: &str) -> Option<char> {
    Some(match s {
        "&lt;" => '<',
        "&gt;" => '>',
        "&amp;" => '&',
        "&quot;" => '"',
        "&apos;" => '\'',
        _ if s.starts_with("&#x") => char::from_u32(u32::from_str_radix(s.trim_start_matches("&#x").trim_end_matches(';'), 16).ok()?)?,
        _ if s.starts_with("&#") => char::from_u32(s.trim_start_matches("&#").trim_end_matches(';').parse().ok()?)?,
        _ => s.chars().next()?,
    })
}

/// One structured-text pass over the whole document: page sizes + glyph boxes.
fn load_pages(pdf: &str, out: &mut File) -> Vec<Page> {
    let r = monitor::run(&["/usr/bin/mutool", "draw", "-q", "-F", "stext", "-o", "-", pdf], WORK, &Opts::new(Net::Deny, Duration::from_secs(180)));
    send_indicators(out, &r.events);
    let xml = r.stdout.unwrap_or_else(|| fail(out, Error::RenderFailed));
    let mut pages: Vec<Page> = Vec::new();
    for line in String::from_utf8_lossy(&xml).lines() {
        let l = line.trim_start();
        if l.starts_with("<page ") {
            let w = attr(l, "width").and_then(|v| v.parse().ok()).unwrap_or(612.0);
            let h = attr(l, "height").and_then(|v| v.parse().ok()).unwrap_or(792.0);
            pages.push(Page { w, h, chars: Vec::new() });
        } else if l.starts_with("<char ") {
            let (Some(p), Some(q), Some(c)) = (pages.last_mut(), attr(l, "quad"), attr(l, "c").and_then(unescape)) else { continue };
            // Only '\n' entries may end a line.
            let c = if c.is_control() { ' ' } else { c };
            let v: Vec<f32> = q.split_whitespace().filter_map(|x| x.parse().ok()).collect();
            if v.len() == 8 && p.chars.len() < 2_000_000 {
                let xs = [v[0], v[2], v[4], v[6]];
                let ys = [v[1], v[3], v[5], v[7]];
                let min = |a: [f32; 4]| a.iter().cloned().fold(f32::MAX, f32::min);
                let max = |a: [f32; 4]| a.iter().cloned().fold(f32::MIN, f32::max);
                p.chars.push((c, [min(xs), min(ys), max(xs), max(ys)]));
            }
        } else if l.starts_with("</line>") {
            if let Some(p) = pages.last_mut() {
                p.chars.push(('\n', [0.0; 4]));
            }
        }
    }
    if pages.is_empty() {
        fail(out, Error::RenderFailed);
    }
    if pages.len() > MAX_PAGES as usize {
        fail(out, Error::TooManyPages);
    }
    pages
}

fn pt10(v: f32) -> u32 {
    (v.max(0.0) * 10.0).round().min(airlock_proto::MAX_PT10 as f32) as u32
}

fn search(pages: &[Page], query: &str) -> Vec<(u32, Vec<[u32; 4]>)> {
    let q: Vec<char> = query.chars().flat_map(char::to_lowercase).collect();
    let mut out = Vec::new();
    if q.is_empty() {
        return out;
    }
    let mut total = 0;
    for (pi, p) in pages.iter().enumerate() {
        let low: Vec<char> = p.chars.iter().map(|(c, _)| c.to_lowercase().next().unwrap_or(*c)).collect();
        let mut rects = Vec::new();
        let mut i = 0;
        while i + q.len() <= low.len() && total < 1000 {
            if low[i..i + q.len()] == q[..] {
                // One rectangle per line the match spans.
                let mut cur: Option<[f32; 4]> = None;
                for (c, b) in &p.chars[i..i + q.len()] {
                    if *c == '\n' {
                        if let Some(r) = cur.take() {
                            rects.push(r);
                        }
                        continue;
                    }
                    cur = Some(match cur {
                        None => *b,
                        Some(r) => [r[0].min(b[0]), r[1].min(b[1]), r[2].max(b[2]), r[3].max(b[3])],
                    });
                }
                rects.extend(cur);
                total += 1;
                i += q.len();
            } else {
                i += 1;
            }
        }
        if !rects.is_empty() {
            out.push((pi as u32, rects.into_iter().map(|r| [pt10(r[0]), pt10(r[1]), pt10(r[2]), pt10(r[3])]).collect()));
        }
    }
    out
}

/// Cuts `text` to the protocol's page-text cap on a char boundary.
fn capped(mut text: String) -> String {
    if text.len() > MAX_PAGE_TEXT as usize {
        let mut cut = MAX_PAGE_TEXT as usize;
        while !text.is_char_boundary(cut) {
            cut -= 1;
        }
        text.truncate(cut);
    }
    text
}

/// Text lines with their bounding boxes, for the app's selectable text layer.
fn lines(p: &Page) -> Vec<([u32; 4], String)> {
    let mut out = Vec::new();
    let mut text = String::new();
    let mut bbox: Option<[f32; 4]> = None;
    let mut bytes = 0;
    for (c, b) in &p.chars {
        if *c == '\n' {
            if let Some(r) = bbox.take() {
                if !text.trim().is_empty() && out.len() < MAX_LINES as usize && bytes + text.len() < MAX_PAGE_TEXT as usize {
                    bytes += text.len() + 1;
                    out.push(([pt10(r[0]), pt10(r[1]), pt10(r[2]), pt10(r[3])], std::mem::take(&mut text)));
                }
            }
            text.clear();
            continue;
        }
        text.push(*c);
        bbox = Some(match bbox {
            None => *b,
            Some(r) => [r[0].min(b[0]), r[1].min(b[1]), r[2].max(b[2]), r[3].max(b[3])],
        });
    }
    out
}

pub fn serve(mut out: File, pdf: &str) -> ! {
    let pages = load_pages(pdf, &mut out);
    let _ = send(&mut out, Kind::Hello, pages.len() as u32, 0, 0, &[]);
    for (i, p) in pages.iter().enumerate() {
        let _ = send(&mut out, Kind::PageInfo, i as u32, pt10(p.w).max(1), pt10(p.h).max(1), &[]);
    }
    crate::log(&format!("live: {} pages ready", pages.len()));

    let mut input = match out.try_clone() {
        Ok(f) => f,
        Err(_) => finish(out),
    };
    loop {
        let mut buf = [0u8; HEADER_LEN];
        if input.read_exact(&mut buf).is_err() {
            finish(out);
        }
        let Some((cmd, h)) = Header::decode_cmd(&buf) else { finish(out) };
        match cmd {
            Cmd::Quit => finish(out),
            Cmd::Render => {
                let Some(p) = pages.get(h.a as usize) else { continue };
                // Never exceed the frame cap: lower the dpi for huge pages.
                let max_dpi = (MAX_DIM as f32 * 72.0 / p.w.max(p.h).max(1.0)).floor() as u32;
                let dpi = h.b.min(max_dpi).max(1).to_string();
                let n = (h.a + 1).to_string();
                let argv = ["/usr/bin/mutool", "draw", "-q", "-r", &dpi, "-c", "rgb", "-F", "pam", "-o", "-", pdf, &n];
                let r = monitor::run(&argv, WORK, &Opts::new(Net::Deny, Duration::from_secs(30)));
                send_indicators(&mut out, &r.events);
                let Some((w, hgt, rgba)) = r.stdout.as_deref().and_then(pam_to_rgba) else { fail(&mut out, Error::RenderFailed) };
                if send(&mut out, Kind::Page, h.a, w, hgt, &rgba).is_err() {
                    finish(out);
                }
            }
            Cmd::Search => {
                let mut q = vec![0u8; h.len as usize];
                if input.read_exact(&mut q).is_err() {
                    finish(out);
                }
                let query = String::from_utf8_lossy(&q).into_owned();
                let hits = search(&pages, &query);
                let mut total = 0u32;
                for (page, rects) in hits {
                    for chunk in rects.chunks(MAX_RECTS as usize) {
                        let payload: Vec<u8> = chunk.iter().flat_map(|r| r.iter().flat_map(|v| v.to_le_bytes())).collect();
                        total += chunk.len() as u32;
                        let _ = send(&mut out, Kind::SearchHits, page, 0, 0, &payload);
                    }
                }
                let _ = send(&mut out, Kind::SearchDone, total, 0, 0, &[]);
            }
            Cmd::GetText => {
                let Some(p) = pages.get(h.a as usize) else { continue };
                let text = capped(p.chars.iter().map(|(c, _)| *c).collect());
                let _ = send(&mut out, Kind::PageText, h.a, 0, 0, text.as_bytes());
            }
            Cmd::GetLayout => {
                let Some(p) = pages.get(h.a as usize) else { continue };
                let ls = lines(p);
                let boxes: Vec<u8> = ls.iter().flat_map(|(r, _)| r.iter().flat_map(|v| v.to_le_bytes())).collect();
                let text = capped(ls.into_iter().map(|(_, t)| t).collect::<Vec<_>>().join("\n"));
                let _ = send(&mut out, Kind::PageLines, h.a, 0, 0, &boxes);
                let _ = send(&mut out, Kind::PageText, h.a, 0, 0, text.as_bytes());
            }
        }
    }
}
