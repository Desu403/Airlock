//! Writes a "clean" PDF that contains nothing but one RGB image per page.
//! It is built from validated pixels only, so no structure from the original
//! document survives: no scripts, links, forms, fonts or embedded files.

use flate2::{write::ZlibEncoder, Compression};
use std::io::Write;

pub struct Page {
    pub width: u32,
    pub height: u32,
    pub rgb: Vec<u8>,
}

pub fn write(pages: &[Page], dpi: f32) -> Vec<u8> {
    let mut w = Writer::new(Vec::new(), pages.len()).expect("writing to memory");
    for p in pages {
        w.add(p, p.width as f32 * 72.0 / dpi, p.height as f32 * 72.0 / dpi).expect("writing to memory");
    }
    w.finish().expect("writing to memory")
}

/// Streams pages out one at a time (a long document never has to fit in
/// memory as pixels). The page count must be known up front.
pub struct Writer<W: Write> {
    out: W,
    pos: usize,
    offsets: Vec<usize>,
    count: usize,
    added: usize,
}

impl<W: Write> Writer<W> {
    pub fn new(out: W, count: usize) -> std::io::Result<Self> {
        let mut w = Writer { out, pos: 0, offsets: Vec::new(), count, added: 0 };
        w.raw(b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n")?;
        // Object numbering: 1 catalog, 2 pages, then 3 objects per page.
        w.obj(b"<< /Type /Catalog /Pages 2 0 R >>")?;
        let kids: Vec<String> = (0..count).map(|i| format!("{} 0 R", 3 + i * 3)).collect();
        w.obj(format!("<< /Type /Pages /Count {count} /Kids [{}] >>", kids.join(" ")).as_bytes())?;
        Ok(w)
    }

    fn raw(&mut self, b: &[u8]) -> std::io::Result<()> {
        self.out.write_all(b)?;
        self.pos += b.len();
        Ok(())
    }

    fn obj(&mut self, body: &[u8]) -> std::io::Result<()> {
        self.offsets.push(self.pos);
        let id = self.offsets.len();
        self.raw(format!("{id} 0 obj\n").as_bytes())?;
        self.raw(body)?;
        self.raw(b"\nendobj\n")
    }

    /// One page: the image `p`, shown at `w_pt` x `h_pt` points.
    pub fn add(&mut self, p: &Page, w_pt: f32, h_pt: f32) -> std::io::Result<()> {
        assert!(self.added < self.count, "more pages than announced");
        let (cid, iid) = (self.offsets.len() + 2, self.offsets.len() + 3);
        self.obj(
            format!(
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {w_pt:.2} {h_pt:.2}] \
                 /Resources << /XObject << /Im0 {iid} 0 R >> >> /Contents {cid} 0 R >>"
            )
            .as_bytes(),
        )?;
        let content = format!("q {w_pt:.2} 0 0 {h_pt:.2} 0 0 cm /Im0 Do Q");
        self.obj(format!("<< /Length {} >>\nstream\n{content}\nendstream", content.len()).as_bytes())?;
        let mut z = ZlibEncoder::new(Vec::new(), Compression::default());
        z.write_all(&p.rgb)?;
        let data = z.finish()?;
        let mut body = format!(
            "<< /Type /XObject /Subtype /Image /Width {} /Height {} /ColorSpace /DeviceRGB \
             /BitsPerComponent 8 /Filter /FlateDecode /Length {} >>\nstream\n",
            p.width,
            p.height,
            data.len()
        )
        .into_bytes();
        body.extend_from_slice(&data);
        body.extend_from_slice(b"\nendstream");
        self.obj(&body)?;
        self.added += 1;
        Ok(())
    }

    pub fn finish(mut self) -> std::io::Result<W> {
        assert_eq!(self.added, self.count, "fewer pages than announced");
        let xref = self.pos;
        let n = self.offsets.len() + 1;
        let mut tail = format!("xref\n0 {n}\n0000000000 65535 f \n");
        for off in &self.offsets {
            tail += &format!("{off:010} 00000 n \n");
        }
        tail += &format!("trailer\n<< /Size {n} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n");
        self.raw(tail.as_bytes())?;
        self.out.flush()?;
        Ok(self.out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every xref entry must point at its "N 0 obj" line.
    #[test]
    fn xref_offsets() {
        let pages: Vec<Page> = (0..3).map(|i| Page { width: 4 + i, height: 3, rgb: vec![i as u8 * 40; (4 + i as usize) * 3 * 3] }).collect();
        let pdf = write(&pages, 72.0);
        let find = |needle: &[u8]| pdf.windows(needle.len()).rposition(|w| w == needle).unwrap();
        let tail = String::from_utf8(pdf[find(b"startxref\n")..].to_vec()).unwrap();
        let xref: usize = tail.lines().nth(1).unwrap().parse().unwrap();
        let table = String::from_utf8(pdf[xref..].to_vec()).unwrap();
        let offsets: Vec<usize> = table.lines().skip(3).take_while(|l| l.ends_with(" n ")).map(|l| l[..10].parse().unwrap()).collect();
        assert_eq!(offsets.len(), 2 + 3 * 3);
        for (i, off) in offsets.iter().enumerate() {
            assert!(pdf[*off..].starts_with(format!("{} 0 obj\n", i + 1).as_bytes()), "object {}", i + 1);
        }
        let text = String::from_utf8_lossy(&pdf);
        assert!(text.contains("/Count 3 /Kids [3 0 R 6 0 R 9 0 R]"));
        assert!(text.ends_with("%%EOF\n"));
    }
}
