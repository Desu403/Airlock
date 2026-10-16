//! Randomised hostile-input testing on stable Rust (no nightly, no
//! coverage guidance): generators for protocol-shaped streams and nasty
//! text, used by the `fuzz_*` tests next to each parser.
//! `AIRLOCK_FUZZ_ITERS=10000000 cargo test --release fuzz` for a long run;
//! `AIRLOCK_FUZZ_SEED` reproduces a failure (each test prints its seed).

use airlock_proto::{Header, MAX_DIM, MAX_LINES, MAX_PAGES, MAX_PAGE_TEXT, MAX_PT10, MAX_RECTS, MAX_TEXT};

pub struct Rng(u64);

impl Rng {
    pub fn from_env(test: &str) -> Self {
        let seed = std::env::var("AIRLOCK_FUZZ_SEED")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64);
        eprintln!("{test}: AIRLOCK_FUZZ_SEED={seed}");
        Rng(seed | 1)
    }
    pub fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
    pub fn chance(&mut self, one_in: usize) -> bool {
        self.below(one_in) == 0
    }
    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
    /// Boundary values first, then anything.
    pub fn field(&mut self) -> u32 {
        const EDGES: [u32; 16] =
            [0, 1, 2, 3, 9, 10, 255, MAX_DIM - 1, MAX_DIM, MAX_DIM + 1, MAX_PAGES - 1, MAX_PAGES, MAX_PT10, MAX_PT10 + 1, u32::MAX / 4 + 1, u32::MAX];
        match self.below(4) {
            0 => self.next() as u32,
            1 => self.below(64) as u32,
            _ => EDGES[self.below(EDGES.len())],
        }
    }
}

pub fn iters(default: u64) -> u64 {
    std::env::var("AIRLOCK_FUZZ_ITERS").ok().and_then(|s| s.parse().ok()).unwrap_or(default)
}

/// Text built from the categories attackers use: controls, bidi, zero
/// widths, tags, private use, noncharacters, invisible fillers, combining
/// floods, complex scripts, emoji sequences, broken UTF-8.
pub fn nasty_text(rng: &mut Rng, max: usize) -> Vec<u8> {
    const POOLS: [(u32, u32); 22] = [
        (0x20, 0x7E), (0x00, 0x1F), (0x7F, 0x9F), (0x0300, 0x036F), (0x202A, 0x202E), (0x2066, 0x2069),
        (0x200B, 0x200F), (0x2028, 0x2029), (0xE0000, 0xE007F), (0xE000, 0xF8FF), (0xFDD0, 0xFDEF),
        (0xFFF0, 0xFFFF), (0x3164, 0x3164), (0x115F, 0x1160), (0xFE00, 0xFE0F), (0x0900, 0x097F),
        (0x0600, 0x06FF), (0x1000, 0x109F), (0x1780, 0x17FF), (0x1F300, 0x1FAFF), (0x4E00, 0x9FFF), (0x10FFFE, 0x10FFFF),
    ];
    let mut out = Vec::new();
    let target = rng.below(max + 1);
    while out.len() < target {
        match rng.below(12) {
            0 => out.push(b'\n'),
            1 => {
                let n = 1 + rng.below(3);
                out.extend(rng.bytes(n)); // likely invalid UTF-8
            }
            2 => out.extend_from_slice(&[0xED, 0xA0, 0x80]), // encoded surrogate
            3 => {
                // a run of one combining mark
                let n = rng.below(40);
                for _ in 0..n {
                    out.extend_from_slice("\u{0301}".as_bytes());
                }
            }
            _ => {
                let (lo, hi) = POOLS[rng.below(POOLS.len())];
                if let Some(c) = char::from_u32(lo + rng.below((hi - lo + 1) as usize) as u32) {
                    let mut b = [0u8; 4];
                    out.extend_from_slice(c.encode_utf8(&mut b).as_bytes());
                }
            }
        }
    }
    out
}

/// A guest->host stream: mostly well-formed headers with hostile values,
/// sometimes lying lengths, truncation, bad magic or plain garbage.
pub fn hostile_stream(rng: &mut Rng) -> Vec<u8> {
    let mut out = Vec::new();
    for _ in 0..1 + rng.below(12) {
        if rng.chance(12) {
            let n = rng.below(48);
            out.extend(rng.bytes(n));
            continue;
        }
        let kind = if rng.chance(10) { rng.field() } else { 1 + rng.below(10) as u32 };
        let (a, mut b, mut c) = (rng.field(), rng.field(), rng.field());
        let payload = match kind {
            2 if !rng.chance(8) => {
                // plausible page: small dimensions, exact length
                (b, c) = (1 + rng.below(40) as u32, 1 + rng.below(40) as u32);
                rng.bytes((b * c * 4) as usize)
            }
            5 => {
                (b, c) = (0, 0);
                let n = rng.below(MAX_TEXT as usize + 8);
                if rng.chance(2) { (0..n).map(|_| 0x20 + rng.below(95) as u8).collect() } else { rng.bytes(n) }
            }
            7 | 10 => {
                (b, c) = (0, 0);
                let cap = if kind == 7 { MAX_RECTS } else { MAX_LINES } as usize;
                let n = if rng.chance(4) { cap + rng.below(3) - 1 } else { rng.below(20) };
                (0..n * 4).flat_map(|_| rng.field().to_le_bytes()).collect()
            }
            9 => {
                (b, c) = (0, 0);
                let max = if rng.chance(50) { MAX_PAGE_TEXT as usize + 64 } else { 3000 };
                nasty_text(rng, max)
            }
            _ => {
                if rng.chance(2) {
                    (b, c) = (0, 0);
                }
                let n = rng.below(32);
                rng.bytes(n)
            }
        };
        let len = if rng.chance(15) { rng.field() } else { payload.len() as u32 };
        let mut h = Header { kind, a, b, c, len }.encode();
        if rng.chance(60) {
            h[rng.below(4)] ^= 1 << rng.below(8);
        }
        out.extend_from_slice(&h);
        // Sometimes truncate the payload.
        let keep = if rng.chance(20) { rng.below(payload.len() + 1) } else { payload.len() };
        out.extend_from_slice(&payload[..keep]);
    }
    out
}
