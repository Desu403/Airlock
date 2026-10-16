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
    let mut out: Vec<u8> = b"%PDF-1.7\n%\xE2\xE3\xCF\xD3\n".to_vec();
    let mut offsets = Vec::new();
    let n = pages.len();
    // Object numbering: 1 catalog, 2 pages, then 3 objects per page.
    let page_obj = |i: usize| 3 + i * 3;

    let obj = |out: &mut Vec<u8>, offsets: &mut Vec<usize>, body: &[u8]| {
        offsets.push(out.len());
        let id = offsets.len();
        out.extend_from_slice(format!("{id} 0 obj\n").as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
    };

    obj(&mut out, &mut offsets, b"<< /Type /Catalog /Pages 2 0 R >>");
    let kids: Vec<String> = (0..n).map(|i| format!("{} 0 R", page_obj(i))).collect();
    obj(&mut out, &mut offsets, format!("<< /Type /Pages /Count {n} /Kids [{}] >>", kids.join(" ")).as_bytes());

    for (i, p) in pages.iter().enumerate() {
        let (w_pt, h_pt) = (p.width as f32 * 72.0 / dpi, p.height as f32 * 72.0 / dpi);
        let (pid, cid, iid) = (page_obj(i), page_obj(i) + 1, page_obj(i) + 2);
        obj(
            &mut out,
            &mut offsets,
            format!(
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {w_pt:.2} {h_pt:.2}] \
                 /Resources << /XObject << /Im0 {iid} 0 R >> >> /Contents {cid} 0 R >>"
            )
            .as_bytes(),
        );
        debug_assert_eq!(offsets.len(), pid);
        let content = format!("q {w_pt:.2} 0 0 {h_pt:.2} 0 0 cm /Im0 Do Q");
        obj(&mut out, &mut offsets, format!("<< /Length {} >>\nstream\n{content}\nendstream", content.len()).as_bytes());
        let mut z = ZlibEncoder::new(Vec::new(), Compression::default());
        z.write_all(&p.rgb).unwrap();
        let data = z.finish().unwrap();
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
        obj(&mut out, &mut offsets, &body);
    }

    let xref = out.len();
    out.extend_from_slice(format!("xref\n0 {}\n0000000000 65535 f \n", offsets.len() + 1).as_bytes());
    for off in &offsets {
        out.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!("trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n", offsets.len() + 1).as_bytes(),
    );
    out
}
