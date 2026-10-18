//! Wire format between the untrusted guest and the trusted host.
//!
//! Design rule: the host must never *parse* attacker-controlled structure.
//! Every message is a fixed 24-byte header of little-endian u32s followed by
//! an optional payload whose length is fully determined by validated header
//! fields. There are no strings, no variable-length encodings and no nesting.
#![cfg_attr(not(test), no_std)]

/// vsock port the guest connects to on the host (CID 2).
pub const FRAME_PORT: u32 = 5000;

pub const MAGIC: [u8; 4] = *b"ALK1";
pub const HEADER_LEN: usize = 24;

/// Hard caps. Anything above these is treated as hostile and kills the VM.
pub const MAX_DIM: u32 = 4096;
pub const MAX_PAGES: u32 = 2000;

/// Header of the document disk the host hands to the guest (read-only).
/// Layout: magic (8 bytes) | doc length u64 LE | doc bytes | zero padding.
pub const DOC_MAGIC: [u8; 8] = *b"ALDOC1\0\0";
pub const DOC_HEADER_LEN: usize = 16;
pub const MAX_DOC_BYTES: u64 = 256 * 1024 * 1024;

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// a = total page count. Sent once, first.
    Hello = 1,
    /// a = page index, b = width, c = height; payload = width*height*4 RGBA.
    Page = 2,
    /// a = pages sent. Last message.
    Done = 3,
    /// a = error code (see `Error`). Last message.
    Error = 4,
    /// a = `Ind` code; payload = 1..=MAX_TEXT bytes of printable ASCII.
    Indicator = 5,
    /// Live: a = page, b = width, c = height (tenths of a point). Sent once
    /// per page right after Hello.
    PageInfo = 6,
    /// Live: a = page; payload = n * 16 bytes of u32 LE rects
    /// (x0, y0, x1, y1 in tenths of a point, top-left origin). Numbers only.
    SearchHits = 7,
    /// Live: a = total hits. Ends a search.
    SearchDone = 8,
    /// Live: a = page; payload = UTF-8 page text (host re-sanitises).
    PageText = 9,
    /// Live: a = page; payload = n * 16 bytes of u32 LE line boxes (tenths
    /// of a point, top-left origin), one per line of the PageText that
    /// follows. Numbers only.
    PageLines = 10,
}

/// Host -> guest commands in live mode (same 24-byte header layout).
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cmd {
    /// a = page, b = dpi.
    Render = 100,
    /// payload = UTF-8 query, 1..=MAX_QUERY bytes.
    Search = 101,
    /// a = page.
    GetText = 102,
    Quit = 103,
    /// a = page. Reply: PageLines, then PageText (one text line per box).
    GetLayout = 104,
    /// a = page. Reply: PageText holding only counts, "key=number" pairs
    /// (characters that the text sanitiser removes: for the AI-text hints).
    TextStats = 105,
    /// An archive's files. Reply: PageText (a = 0) with one line per file,
    /// "index size flags name" (flags: comma-separated words, or "-").
    Entries = 106,
}

pub const MAX_QUERY: u32 = 256;
pub const MAX_PAGE_TEXT: u32 = 256 * 1024;
pub const MAX_RECTS: u32 = 256;
pub const MAX_LINES: u32 = 8192;
pub const MAX_PT10: u32 = 1_000_000;
pub const MIN_DPI: u32 = 20;
pub const MAX_DPI: u32 = 600;

impl Header {
    /// Guest-side validation of a host command.
    pub fn decode_cmd(buf: &[u8; HEADER_LEN]) -> Option<(Cmd, Self)> {
        let h = Self::decode_raw(buf)?;
        let cmd = match h.kind {
            100 if (MIN_DPI..=MAX_DPI).contains(&h.b) && h.a < MAX_PAGES && h.len == 0 => Cmd::Render,
            101 if (1..=MAX_QUERY).contains(&h.len) => Cmd::Search,
            102 if h.a < MAX_PAGES && h.len == 0 => Cmd::GetText,
            103 if h.len == 0 => Cmd::Quit,
            104 if h.a < MAX_PAGES && h.len == 0 => Cmd::GetLayout,
            105 if h.a < MAX_PAGES && h.len == 0 => Cmd::TextStats,
            106 if h.a == 0 && h.b == 0 && h.len == 0 => Cmd::Entries,
            _ => return None,
        };
        Some((cmd, h))
    }

    fn decode_raw(buf: &[u8; HEADER_LEN]) -> Option<Self> {
        if buf[0..4] != MAGIC {
            return None;
        }
        let f = |i: usize| u32::from_le_bytes([buf[4 + i * 4], buf[5 + i * 4], buf[6 + i * 4], buf[7 + i * 4]]);
        Some(Header { kind: f(0), a: f(1), b: f(2), c: f(3), len: f(4) })
    }
}

/// Longest text a guest may attach to an indicator.
pub const MAX_TEXT: u32 = 240;

/// The only text the host ever accepts from a guest: short printable ASCII.
pub fn valid_text(b: &[u8]) -> bool {
    !b.is_empty() && b.len() <= MAX_TEXT as usize && b.iter().all(|c| (0x20..=0x7e).contains(c))
}

/// Squashes arbitrary bytes into something `valid_text` accepts.
pub fn sanitize_into(src: &[u8], out: &mut [u8; MAX_TEXT as usize]) -> usize {
    let n = src.len().min(out.len());
    for (o, &c) in out.iter_mut().zip(&src[..n]) {
        *o = if (0x20..=0x7e).contains(&c) { c } else { b'?' };
    }
    if n == 0 {
        out[0] = b'-';
        return 1;
    }
    n
}

/// Things a guest can report. The host decides what they *mean*
/// (severity, ATT&CK mapping); the guest only supplies the code and text.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ind {
    /// Static: active-content feature in the PDF ("JavaScript x2").
    PdfFeature = 1,
    /// Static: link target found in the PDF.
    PdfUri = 2,
    /// Static: first characters of embedded JavaScript.
    PdfJs = 3,
    /// Static: obfuscation trick (hex-escaped names, ...).
    PdfObfuscation = 4,
    /// Emulation: the document's JavaScript called a reader API ("net: app.launchURL(...)").
    JsCall = 5,
    /// Emulation: known exploit pattern (CVE trigger, shellcode, heap spray).
    JsExploit = 6,
    /// Emulation: a deobfuscation layer (code passed to eval/Function).
    JsEval = 7,
    /// Emulation: script error (often: uses an API we do not fake).
    JsError = 8,
    /// Monitor: renderer tried to execute a program.
    Exec = 10,
    /// Monitor: renderer tried to create a process.
    ProcessCreate = 11,
    /// Monitor: renderer opened a socket.
    Socket = 12,
    /// Monitor: renderer connected / sent somewhere.
    Connect = 13,
    /// Monitor: syscall that only makes sense to attack the kernel.
    KernelSurface = 14,
    /// Monitor: ptrace / cross-process memory access.
    Ptrace = 15,
    /// Monitor: renderer crashed, timed out or hit the event cap.
    RendererAbnormal = 16,
    /// Autopsy: file left behind on the scratch disk.
    FileDropped = 20,
    /// Office: VBA module present (name, size, first lines).
    OfficeMacro = 30,
    /// Office: macro runs automatically (AutoOpen, Document_Open, ...).
    OfficeAutoExec = 31,
    /// Office: suspicious macro keyword (Shell, CreateObject, ...).
    OfficeSuspicious = 32,
    /// Office: URL/IP/executable name found in macros.
    OfficeIoc = 33,
    /// Office: encoded/obfuscated strings in macros.
    OfficeObfuscation = 34,
    /// Office: VBA stomping (source does not match compiled p-code).
    OfficeStomping = 35,
    /// Office: Excel 4.0 / XLM macros.
    OfficeXlm = 36,
    /// Office: external relationship / remote template.
    OfficeExternal = 37,
    /// Office: known exploit pattern (Follina, DDE, Equation Editor, ...).
    OfficeExploit = 38,
    /// Office: embedded object / ActiveX / packaged file.
    OfficeEmbedded = 39,
    /// Office: hyperlink target.
    OfficeLink = 40,
    /// Office: container property (macro-enabled format, ...).
    OfficeContainer = 41,
    /// Office: triage could not parse something.
    OfficeError = 42,
    /// YARA: a known-malware rule matched (rule score >= 75).
    YaraHigh = 50,
    /// YARA: a rule for suspicious-but-not-conclusive traits (score 60-74).
    YaraMedium = 51,
    /// YARA: weak or generic rule.
    YaraLow = 52,
    /// PDF: an action that runs without the reader doing anything ("Launch: cmd.exe [document opened]").
    PdfAutoAction = 60,
    /// PDF: an action that runs if the reader clicks (links are PdfUri).
    PdfClickAction = 61,
    /// PDF: embedded file ("name (size, what it is)").
    PdfAttachment = 62,
    /// PDF: form scripts that only call Adobe's standard formatting functions.
    PdfJsForm = 63,
    /// PDF: JavaScript that only runs on a click or keystroke, or never.
    PdfJsClick = 64,
    /// PDF: structure could not be read (password, damage, deliberate malformation).
    PdfUnreadable = 65,
    /// PDF: a web link covering a large part of a page (phishing lure).
    PdfLure = 66,
    /// Data hidden after a document's end, or a file that is two formats at once.
    HiddenData = 67,
    /// A QR code on a page, and where it leads.
    QrLink = 68,
    /// Phishing wording on the first pages (brand + request + elsewhere link,
    /// or a callback scam).
    PhishText = 69,
    /// A script (text file) with a dangerous pattern; the text starts with
    /// its kind: "download-run", "hidden-powershell", "smuggling", "shell",
    /// "obfuscated".
    Script = 70,
}

impl Ind {
    pub fn from_u32(v: u32) -> Option<Self> {
        use Ind::*;
        Some(match v {
            1 => PdfFeature,
            2 => PdfUri,
            3 => PdfJs,
            4 => PdfObfuscation,
            5 => JsCall,
            6 => JsExploit,
            7 => JsEval,
            8 => JsError,
            10 => Exec,
            11 => ProcessCreate,
            12 => Socket,
            13 => Connect,
            14 => KernelSurface,
            15 => Ptrace,
            16 => RendererAbnormal,
            20 => FileDropped,
            30 => OfficeMacro,
            31 => OfficeAutoExec,
            32 => OfficeSuspicious,
            33 => OfficeIoc,
            34 => OfficeObfuscation,
            35 => OfficeStomping,
            36 => OfficeXlm,
            37 => OfficeExternal,
            38 => OfficeExploit,
            39 => OfficeEmbedded,
            40 => OfficeLink,
            41 => OfficeContainer,
            42 => OfficeError,
            50 => YaraHigh,
            51 => YaraMedium,
            52 => YaraLow,
            60 => PdfAutoAction,
            61 => PdfClickAction,
            62 => PdfAttachment,
            63 => PdfJsForm,
            64 => PdfJsClick,
            65 => PdfUnreadable,
            66 => PdfLure,
            67 => HiddenData,
            68 => QrLink,
            69 => PhishText,
            70 => Script,
            _ => return None,
        })
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    BadDocDisk = 1,
    UnsupportedType = 2,
    RenderFailed = 3,
    TooManyPages = 4,
    Internal = 5,
}

impl Error {
    pub fn from_u32(v: u32) -> Option<Self> {
        Some(match v {
            1 => Self::BadDocDisk,
            2 => Self::UnsupportedType,
            3 => Self::RenderFailed,
            4 => Self::TooManyPages,
            5 => Self::Internal,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub kind: u32,
    pub a: u32,
    pub b: u32,
    pub c: u32,
    pub len: u32,
}

impl Header {
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0..4].copy_from_slice(&MAGIC);
        for (i, v) in [self.kind, self.a, self.b, self.c, self.len].iter().enumerate() {
            out[4 + i * 4..8 + i * 4].copy_from_slice(&v.to_le_bytes());
        }
        out
    }

    /// Decodes and validates a header. Returns `None` for anything that is not
    /// exactly one of the allowed shapes; the host treats `None` as hostile.
    pub fn decode(buf: &[u8; HEADER_LEN]) -> Option<Self> {
        let h = Self::decode_raw(buf)?;
        let ok = match h.kind {
            k if k == Kind::Hello as u32 => h.a >= 1 && h.a <= MAX_PAGES && h.b == 0 && h.c == 0 && h.len == 0,
            k if k == Kind::Page as u32 => {
                h.a < MAX_PAGES
                    && (1..=MAX_DIM).contains(&h.b)
                    && (1..=MAX_DIM).contains(&h.c)
                    && h.len as u64 == h.b as u64 * h.c as u64 * 4
            }
            k if k == Kind::Done as u32 => h.a <= MAX_PAGES && h.b == 0 && h.c == 0 && h.len == 0,
            k if k == Kind::Error as u32 => Error::from_u32(h.a).is_some() && h.b == 0 && h.c == 0 && h.len == 0,
            k if k == Kind::Indicator as u32 => {
                Ind::from_u32(h.a).is_some() && h.b == 0 && h.c == 0 && (1..=MAX_TEXT).contains(&h.len)
            }
            k if k == Kind::PageInfo as u32 => {
                h.a < MAX_PAGES && (1..=MAX_PT10).contains(&h.b) && (1..=MAX_PT10).contains(&h.c) && h.len == 0
            }
            k if k == Kind::SearchHits as u32 => {
                h.a < MAX_PAGES && h.b == 0 && h.c == 0 && h.len > 0 && h.len % 16 == 0 && h.len <= MAX_RECTS * 16
            }
            k if k == Kind::SearchDone as u32 => h.b == 0 && h.c == 0 && h.len == 0,
            k if k == Kind::PageText as u32 => h.a < MAX_PAGES && h.b == 0 && h.c == 0 && h.len <= MAX_PAGE_TEXT,
            k if k == Kind::PageLines as u32 => {
                h.a < MAX_PAGES && h.b == 0 && h.c == 0 && h.len % 16 == 0 && h.len <= MAX_LINES * 16
            }
            _ => false,
        };
        ok.then_some(h)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(kind: u32, a: u32, b: u32, c: u32, len: u32) -> [u8; HEADER_LEN] {
        Header { kind, a, b, c, len }.encode()
    }

    #[test]
    fn accepts_well_formed() {
        assert!(Header::decode(&h(1, 3, 0, 0, 0)).is_some());
        assert!(Header::decode(&h(2, 0, 100, 50, 100 * 50 * 4)).is_some());
        assert!(Header::decode(&h(3, 3, 0, 0, 0)).is_some());
        assert!(Header::decode(&h(4, 2, 0, 0, 0)).is_some());
        assert!(Header::decode(&h(5, 13, 0, 0, 20)).is_some());
        assert!(Header::decode(&h(6, 0, 6120, 7920, 0)).is_some());
        assert!(Header::decode(&h(7, 2, 0, 0, 32)).is_some());
        assert!(Header::decode(&h(9, 2, 0, 0, 100)).is_some());
        assert!(Header::decode(&h(10, 2, 0, 0, 0)).is_some());
        assert!(Header::decode(&h(10, 2, 0, 0, 160)).is_some());
    }

    #[test]
    fn live_shapes() {
        assert!(Header::decode(&h(7, 2, 0, 0, 20)).is_none()); // not a multiple of 16
        assert!(Header::decode(&h(7, 2, 0, 0, (MAX_RECTS + 1) * 16)).is_none());
        assert!(Header::decode(&h(9, 2, 0, 0, MAX_PAGE_TEXT + 1)).is_none());
        assert!(Header::decode(&h(6, 0, 0, 7920, 0)).is_none());
        assert!(Header::decode(&h(10, 2, 0, 0, 24)).is_none());
        assert!(Header::decode(&h(10, 2, 0, 0, (MAX_LINES + 1) * 16)).is_none());
        assert!(Header::decode_cmd(&h(104, 1, 0, 0, 0)).is_some());
        assert!(Header::decode_cmd(&h(104, 1, 0, 0, 4)).is_none());
        // Commands are only accepted by decode_cmd, and vice versa.
        assert!(Header::decode(&h(100, 0, 150, 0, 0)).is_none());
        assert!(Header::decode_cmd(&h(100, 0, 150, 0, 0)).is_some());
        assert!(Header::decode_cmd(&h(100, 0, 5000, 0, 0)).is_none());
        assert!(Header::decode_cmd(&h(2, 0, 10, 10, 400)).is_none());
    }

    #[test]
    fn text_rules() {
        assert!(valid_text(b"203.0.113.7:443"));
        assert!(!valid_text(b""));
        assert!(!valid_text(b"\x1b[2J"[..].iter().map(|_| 0x1bu8).collect::<std::vec::Vec<_>>().as_slice()));
        assert!(!valid_text(b"line\nbreak"));
        let mut out = [0u8; MAX_TEXT as usize];
        let n = sanitize_into(b"\x1b]0;pwn\x07ok", &mut out);
        assert!(valid_text(&out[..n]));
    }

    #[test]
    fn rejects_hostile_shapes() {
        let bad = [
            h(2, 0, 100, 50, 100 * 50 * 4 + 1), // payload length lies
            h(2, 0, 0, 50, 0),                  // zero width
            h(2, 0, MAX_DIM + 1, 1, (MAX_DIM + 1) * 4),
            h(2, 0, 65536, 65536, 0),           // u32 overflow attempt
            h(2, MAX_PAGES, 1, 1, 4),
            h(1, 0, 0, 0, 0),
            h(1, MAX_PAGES + 1, 0, 0, 0),
            h(1, 3, 0, 0, 16),                  // hello with a payload
            h(4, 99, 0, 0, 0),                  // unknown error code
            h(99, 0, 0, 0, 0),                  // unknown kind
            h(5, 10, 0, 0, 0),                  // indicator without text
            h(5, 10, 0, 0, MAX_TEXT + 1),       // indicator text too long
            h(5, 999, 0, 0, 10),                // unknown indicator
        ];
        for b in bad {
            assert!(Header::decode(&b).is_none(), "{b:?}");
        }
        let mut wrong_magic = h(1, 3, 0, 0, 0);
        wrong_magic[0] = b'X';
        assert!(Header::decode(&wrong_magic).is_none());
    }
}

#[cfg(test)]
mod fuzz {
    use super::*;

    /// Random headers biased towards valid kinds and boundary values:
    /// whatever `decode` accepts must have a bounded, self-consistent shape.
    #[test]
    fn fuzz_decode() {
        let mut x = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64 | 1;
        eprintln!("fuzz_decode seed {x}");
        let mut next = move || {
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };
        const EDGES: [u32; 12] = [0, 1, 16, 4, MAX_DIM, MAX_DIM + 1, MAX_PAGES, MAX_TEXT, MAX_PAGE_TEXT, MAX_LINES * 16, MAX_PT10, u32::MAX];
        let iters = std::env::var("AIRLOCK_FUZZ_ITERS").ok().and_then(|s| s.parse().ok()).unwrap_or(2_000_000u64);
        for _ in 0..iters {
            let f = |r: u64, v: u64| match r % 3 {
                0 => v as u32,
                1 => (v % 64) as u32,
                _ => EDGES[(v % EDGES.len() as u64) as usize],
            };
            let r = next();
            let kind = if r % 4 == 0 { f(next(), next()) } else { [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 100, 101, 102, 103, 104][(r % 15) as usize] };
            let (a, b, c) = (f(next(), next()), f(next(), next()), f(next(), next()));
            let len = if kind == 2 && next() % 2 == 0 { b.wrapping_mul(c).wrapping_mul(4) } else { f(next(), next()) };
            let buf = Header { kind, a, b, c, len }.encode();
            if let Some(h) = Header::decode(&buf) {
                assert_eq!(h.encode(), buf);
                let max = (MAX_DIM * MAX_DIM * 4).max(MAX_PAGE_TEXT).max(MAX_LINES * 16);
                assert!(h.len <= max, "{h:?}");
                match h.kind {
                    2 => assert!(h.b >= 1 && h.b <= MAX_DIM && h.c >= 1 && h.c <= MAX_DIM && h.len as u64 == h.b as u64 * h.c as u64 * 4, "{h:?}"),
                    5 => assert!(h.len >= 1 && h.len <= MAX_TEXT && Ind::from_u32(h.a).is_some(), "{h:?}"),
                    7 | 10 => assert!(h.len % 16 == 0 && h.a < MAX_PAGES, "{h:?}"),
                    1 | 3 | 4 | 6 | 8 => assert_eq!(h.len, 0, "{h:?}"),
                    9 => assert!(h.len <= MAX_PAGE_TEXT && h.a < MAX_PAGES),
                    k => panic!("decode accepted kind {k}"),
                }
            }
            if let Some((cmd, h)) = Header::decode_cmd(&buf) {
                match cmd {
                    Cmd::Search => assert!(h.len >= 1 && h.len <= MAX_QUERY),
                    Cmd::Render => assert!(h.len == 0 && h.a < MAX_PAGES && (MIN_DPI..=MAX_DPI).contains(&h.b)),
                    Cmd::GetText | Cmd::GetLayout | Cmd::TextStats => assert!(h.len == 0 && h.a < MAX_PAGES),
                    Cmd::Quit => assert_eq!(h.len, 0),
                    Cmd::Entries => assert!(h.len == 0 && h.a == 0 && h.b == 0),
                }
            }
        }
    }
}
