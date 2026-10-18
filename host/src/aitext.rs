//! Hints that a document's text came out of an AI chat tool: characters and
//! leftovers those tools put into pasted text, and stock phrasing. These are
//! hints, never proof: people write like this too, and AI text can be cleaned.
//! Strong signs are artefacts nobody types (citation tokens, private-use
//! citation markers, "As an AI language model"); weak signs only add up.

use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub struct Signal {
    /// "strong" or "weak"
    pub strength: &'static str,
    pub title: String,
    pub detail: String,
}

#[derive(Debug)]
pub struct AiHints {
    /// "none", "some", "strong"
    pub level: &'static str,
    pub summary: &'static str,
    pub signals: Vec<Signal>,
    pub words: u64,
}

/// Phrases chat assistants overuse (lower case). Weak on their own.
const STOCK: &[&str] = &[
    "delve", "tapestry", "it's important to note", "it is important to note", "it's worth noting", "it is worth noting", "in today's fast-paced",
    "in the ever-evolving", "ever-evolving", "a testament to", "plays a crucial role", "plays a pivotal role", "multifaceted", "navigate the complexities",
    "unlock the potential", "embark on", "in the realm of", "underscores the importance", "fostering", "seamlessly", "a rich tapestry",
    "let's dive in", "dive into", "in conclusion,", "in summary,", "overall,", "furthermore,", "moreover,", "additionally,", "notably,",
    "elevate your", "game-changer", "cutting-edge", "robust", "leverage", "holistic", "paradigm", "synergy",
];

/// Things a person almost never leaves in a finished document (lower case).
const TELLS: &[(&str, &str)] = &[
    ("as an ai language model", "\"As an AI language model\""),
    ("as an ai model", "\"As an AI model\""),
    ("as a large language model", "\"As a large language model\""),
    ("i hope this helps", "\"I hope this helps\""),
    ("certainly! here", "\"Certainly! Here is…\""),
    ("sure! here", "\"Sure! Here is…\""),
    ("here's a revised version", "\"Here's a revised version\""),
    ("as of my last update", "\"As of my last update\""),
    ("as of my knowledge cutoff", "\"As of my knowledge cutoff\""),
    ("i cannot fulfill", "\"I cannot fulfill…\""),
    ("[insert ", "a template placeholder \"[insert …]\""),
    ("[your name]", "a template placeholder \"[Your Name]\""),
    ("[company name]", "a template placeholder \"[Company Name]\""),
    ("regenerate response", "a \"Regenerate response\" button label"),
];

impl AiHints {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "level": self.level,
            "summary": self.summary,
            "words": self.words,
            "signals": self.signals.iter().map(|s| serde_json::json!({"strength": s.strength, "title": s.title, "detail": s.detail})).collect::<Vec<_>>(),
        })
    }
}

fn per_k(n: u64, words: u64) -> f64 {
    n as f64 * 1000.0 / words.max(1) as f64
}

/// `stats`: per-page counts from the VM (Cmd::TextStats), summed.
/// `text`: the sanitised text of the same pages.
pub fn analyze(stats: &BTreeMap<String, u64>, text: &str) -> AiHints {
    let get = |k: &str| stats.get(k).copied().unwrap_or(0);
    let words = get("words").max(text.split_whitespace().count() as u64);
    let lower = text.to_lowercase();
    let mut signals = Vec::new();
    let mut strong = |title: String, detail: String| signals.push(Signal { strength: "strong", title, detail });

    if get("cite") > 0 {
        strong("Leftover AI citation codes".into(), format!("{} citation token(s) such as \"oaicite\" or \"turn0search\": what ChatGPT's web answers contain when copied", get("cite")));
    }
    if get("pua") > 0 && get("brackets") > 0 {
        strong("Hidden citation markers".into(), format!("{} private-use characters with 【 】 brackets: the invisible markers chat tools put around sources", get("pua")));
    }
    for (needle, what) in TELLS {
        if lower.contains(needle) {
            strong("Chat-assistant wording left in".into(), format!("contains {what}"));
        }
    }

    let mut weak = Vec::new();
    if get("zw") > 0 {
        weak.push(Signal { strength: "weak", title: "Invisible characters".into(), detail: format!("{} zero-width character(s): pasted text from chat tools and web pages often carries them", get("zw")) });
    }
    if get("nnbsp") > 2 {
        weak.push(Signal { strength: "weak", title: "Unusual spaces".into(), detail: format!("{} narrow no-break spaces (U+202F), rare in typed text", get("nnbsp")) });
    }
    if words >= 150 && per_k(get("emdash"), words) >= 6.0 {
        weak.push(Signal { strength: "weak", title: "Many em dashes".into(), detail: format!("{} em dashes (—) in {} words; chat assistants use them heavily", get("emdash"), words) });
    }
    let stock: Vec<&str> = STOCK.iter().copied().filter(|p| lower.contains(p)).collect();
    if words >= 150 && stock.len() >= 4 {
        weak.push(Signal { strength: "weak", title: "Stock assistant phrasing".into(), detail: format!("{} typical phrases: {}", stock.len(), stock.iter().take(8).map(|s| format!("\"{s}\"")).collect::<Vec<_>>().join(", ")) });
    }
    let md_lines = text.lines().filter(|l| { let l = l.trim_start(); l.starts_with("### ") || l.starts_with("## ") || l.starts_with("**") || l.starts_with("- **") || l.starts_with("```") }).count();
    let bold = text.matches("**").count() / 2;
    if md_lines >= 2 || bold >= 3 {
        weak.push(Signal { strength: "weak", title: "Unrendered Markdown".into(), detail: format!("{} heading/bold markers like \"###\" or \"**…**\" printed as text, as when a chat answer is pasted", md_lines + bold) });
    }

    let n_strong = signals.len();
    signals.extend(weak);
    let (level, summary) = if n_strong > 0 {
        ("strong", "Strong signs that text was pasted from an AI chat tool. This does not say who wrote the rest, or whether the content is right.")
    } else if signals.len() >= 2 {
        ("some", "Some typical signs of AI-written text. People write like this too: treat it as a hint, not proof.")
    } else if signals.len() == 1 {
        ("none", "One weak sign only: not enough to say anything.")
    } else {
        ("none", "No typical signs of AI-written text. That does not prove a person wrote it: AI text can be edited to remove them.")
    };
    AiHints { level, summary, signals, words }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn stats(pairs: &[(&str, u64)]) -> BTreeMap<String, u64> {
        pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect()
    }
    #[test]
    fn strong_and_weak_signs() {
        let h = analyze(&stats(&[("words", 300), ("cite", 2)]), "Results are good.");
        assert_eq!(h.level, "strong");
        let h = analyze(&stats(&[("words", 40)]), "As an AI language model, I cannot browse.");
        assert_eq!(h.level, "strong");
        let body = "It is important to note that we delve into a rich tapestry. Moreover, the multifaceted approach plays a crucial role — overall, seamlessly. ".repeat(20);
        let h = analyze(&stats(&[("words", 400), ("emdash", 20), ("zw", 3)]), &body);
        assert_eq!(h.level, "some", "{h:?}");
        let h = analyze(&stats(&[("words", 500)]), &"The committee met on Tuesday and approved the budget for next year. ".repeat(40));
        assert_eq!(h.level, "none");
        assert!(h.signals.is_empty());
    }
}
