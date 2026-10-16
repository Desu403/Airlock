//! Page text is the only free-form data that leaves a VM, and the app hands
//! it to the system's text stack (HarfBuzz, FreeType) running as the user.
//! That is the one path where a single bug could be enough, so the text is
//! narrowed to ordinary, assigned, visible characters (NFC-normalised),
//! with bounded combining-mark runs and line lengths.

use unicode_general_category::{get_general_category, GeneralCategory as G};
use unicode_normalization::UnicodeNormalization;

/// Characters kept per line; the rest of an over-long line is dropped.
pub const MAX_LINE_CHARS: usize = 1000;
/// Combining marks kept per base character ("Zalgo" floods are cut).
pub const MAX_MARKS: usize = 3;

const ZWNJ: char = '\u{200C}';
const ZWJ: char = '\u{200D}';

/// Cleans attacker-controlled text. Line breaks are preserved one-for-one
/// (the selectable text layer pairs lines with boxes); everything else that
/// is not an ordinary visible character is removed.
pub fn sanitize(raw: &[u8]) -> String {
    // Normalise first, then enforce the limits last, so they hold on exactly
    // what is displayed (NFC can split a character into base + mark, e.g.
    // U+0959, and composing after filtering can merge two mark runs).
    let src: String = String::from_utf8_lossy(raw).nfc().collect();
    let mut kept = String::with_capacity(src.len());
    let (mut marks, mut line) = (0, 0);
    for c in src.chars() {
        if c == '\n' {
            kept.push('\n');
            (marks, line) = (0, 0);
            continue;
        }
        let c = match c {
            '\t' | '\u{2028}' | '\u{2029}' => ' ',
            c => c,
        };
        if !allowed(c) || line >= MAX_LINE_CHARS {
            continue;
        }
        if matches!(get_general_category(c), G::NonspacingMark | G::SpacingMark | G::EnclosingMark) {
            marks += 1;
            if marks > MAX_MARKS {
                continue;
            }
        } else {
            marks = 0;
        }
        line += 1;
        kept.push(c);
    }
    kept
}

/// One line of text (e.g. a file name): line breaks become spaces.
pub fn sanitize_line(raw: &[u8]) -> String {
    sanitize(raw).replace('\n', " ")
}

pub(crate) fn allowed(c: char) -> bool {
    match get_general_category(c) {
        // Joiners are needed by Indic/Persian text and emoji.
        G::Control | G::Format => c == ZWJ || c == ZWNJ,
        G::Surrogate | G::PrivateUse | G::Unassigned | G::LineSeparator | G::ParagraphSeparator => false,
        _ => !invisible(c) && !noncharacter(c),
    }
}

/// Default-ignorable code points that are not Format/Control: they render
/// as nothing and are used to hide or spoof text. Text and emoji
/// presentation selectors (FE0E/FE0F) stay.
fn invisible(c: char) -> bool {
    matches!(c,
        '\u{034F}' | '\u{115F}' | '\u{1160}' | '\u{17B4}' | '\u{17B5}' | '\u{180B}'..='\u{180F}'
        | '\u{3164}' | '\u{FE00}'..='\u{FE0D}' | '\u{FFA0}' | '\u{FFF0}'..='\u{FFF8}'
        | '\u{1BCA0}'..='\u{1BCA3}' | '\u{1D173}'..='\u{1D17A}' | '\u{E0000}'..='\u{E0FFF}')
}

fn noncharacter(c: char) -> bool {
    let v = c as u32;
    (0xFDD0..=0xFDEF).contains(&v) || v & 0xFFFE == 0xFFFE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trojan_source_and_controls() {
        let evil = "pay\u{202E}fdp.exe\u{1b}[2J\u{7}ok\nline2\u{2066}x";
        assert_eq!(sanitize(evil.as_bytes()), "payfdp.exe[2Jok\nline2x");
        assert_eq!(sanitize(b"\xff\xfeA"), "\u{FFFD}\u{FFFD}A");
    }

    #[test]
    fn invisible_and_private() {
        let s = "a\u{200B}b\u{FEFF}c\u{3164}d\u{E0041}e\u{F8FF}f\u{10FFFF}g\u{FDD0}h\u{FE01}i\u{AD}j";
        assert_eq!(sanitize(s.as_bytes()), "abcdefghij");
    }

    #[test]
    fn real_scripts_survive() {
        for s in ["Grüße, Ελληνικά, Кириллица", "العربية", "हिन्दी", "日本語のテキスト", "한국어", "👩\u{200D}💻 ok\u{FE0F}", "می\u{200C}خواهم"] {
            assert_eq!(sanitize(s.as_bytes()), s.nfc().collect::<String>(), "{s}");
        }
    }

    #[test]
    fn zalgo_is_capped() {
        let s = format!("Z{}a", "\u{0301}\u{0302}\u{0303}\u{0304}".repeat(50));
        // Z + U+0301 composes to Ź first; then three marks are kept.
        assert_eq!(sanitize(s.as_bytes()), "\u{0179}\u{0302}\u{0303}\u{0304}a");
    }

    #[test]
    fn lines_are_preserved_and_capped() {
        let s = format!("{}\n\u{2028}x\ty\n", "a".repeat(5000));
        let out = sanitize(s.as_bytes());
        let lines: Vec<&str> = out.split('\n').collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0].chars().count(), MAX_LINE_CHARS);
        assert_eq!(lines[1], " x y");
        assert_eq!(sanitize_line(b"a\nb"), "a b");
    }

    /// Invariants every sanitised text must satisfy.
    pub(crate) fn check(raw: &[u8], out: &str) {
        let lossy = String::from_utf8_lossy(raw);
        assert_eq!(out.matches('\n').count(), lossy.matches('\n').count(), "line breaks must map one-to-one");
        for line in out.split('\n') {
            assert!(line.chars().count() <= MAX_LINE_CHARS, "line too long");
            let mut run = 0;
            for c in line.chars() {
                assert!(allowed(c), "{c:?} (U+{:04X}) survived", c as u32);
                if matches!(get_general_category(c), G::NonspacingMark | G::SpacingMark | G::EnclosingMark) {
                    run += 1;
                    assert!(run <= MAX_MARKS, "combining run of {run} survived");
                } else {
                    run = 0;
                }
            }
        }
    }

    #[test]
    fn fuzz_sanitize() {
        let mut rng = crate::fuzz::Rng::from_env("fuzz_sanitize");
        for _ in 0..crate::fuzz::iters(20_000) {
            let raw = crate::fuzz::nasty_text(&mut rng, 3000);
            let out = sanitize(&raw);
            check(&raw, &out);
            check(out.as_bytes(), &sanitize(out.as_bytes()));
        }
    }

    #[test]
    fn composes_to_nfc() {
        assert_eq!(sanitize("e\u{0301}".as_bytes()), "\u{e9}");
    }
}
