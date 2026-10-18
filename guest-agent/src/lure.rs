//! Phishing content in what the document *shows*: QR codes and the wording
//! of its first pages. Attacks that carry no code at all (a page that is a
//! fake "View document" button, an invoice asking you to call a number)
//! are only visible here. Runs in the analysis VM, as nobody, under the
//! monitor, without network; works on the rendered PDF (Office files after
//! conversion).

use crate::monitor::{self, Net, Opts};
use airlock_proto::Ind;
use std::time::Duration;

const PAGES: &str = "1-3";

/// Brands phishing pages imitate, with the domains that really are theirs.
const BRANDS: &[(&str, &[&str])] = &[
    ("Microsoft", &["microsoft.com", "office.com", "live.com", "sharepoint.com", "onedrive.com", "office365.com", "microsoftonline.com", "outlook.com", "aka.ms", "1drv.ms", "windows.com", "msn.com", "cloud.microsoft"]),
    ("Office 365", &["microsoft.com", "office.com", "office365.com", "microsoftonline.com", "sharepoint.com", "cloud.microsoft"]),
    ("OneDrive", &["microsoft.com", "onedrive.com", "live.com", "1drv.ms", "sharepoint.com"]),
    ("SharePoint", &["microsoft.com", "sharepoint.com"]),
    ("Outlook", &["microsoft.com", "outlook.com", "live.com", "office.com"]),
    ("Adobe", &["adobe.com", "adobe.io", "acrobat.com", "adobesign.com", "echosign.com", "adobe.ly"]),
    ("Acrobat", &["adobe.com", "acrobat.com", "adobe.io"]),
    ("DocuSign", &["docusign.com", "docusign.net"]),
    ("PayPal", &["paypal.com", "paypal.me"]),
    ("Facebook", &["facebook.com", "fb.com", "fb.me", "meta.com"]),
    ("Meta ©", &["facebook.com", "fb.com", "meta.com", "instagram.com"]),
    ("© Meta", &["facebook.com", "fb.com", "meta.com", "instagram.com"]),
    ("Meta Platforms", &["facebook.com", "fb.com", "meta.com", "instagram.com"]),
    ("Malwarebytes", &["malwarebytes.com"]),
    ("Kaspersky", &["kaspersky.com"]),
    ("Bitdefender", &["bitdefender.com"]),
    ("Windows Defender", &["microsoft.com"]),
    ("Instagram", &["instagram.com", "meta.com"]),
    ("Apple", &["apple.com", "icloud.com"]),
    ("Netflix", &["netflix.com"]),
    ("Amazon", &["amazon.com", "amazon.de", "amazon.co.uk", "amazon.fr", "amazon.it", "amazon.es", "amzn.to", "aws.amazon.com"]),
    ("DHL", &["dhl.com", "dhl.de"]),
    ("FedEx", &["fedex.com"]),
    ("Dropbox", &["dropbox.com"]),
    ("WeTransfer", &["wetransfer.com", "we.tl"]),
    ("Google Drive", &["google.com"]),
    ("Norton", &["norton.com"]),
    ("McAfee", &["mcafee.com"]),
    ("Avast", &["avast.com"]),
    ("Geek Squad", &["geeksquad.com", "bestbuy.com"]),
    ("Coinbase", &["coinbase.com"]),
];

/// "Open/view the document", "verify your account": the page asks for a click.
const ACTION: &[&str] = &[
    "view document", "open document", "view the document", "access document", "review document", "shared a document", "shared document",
    "view pdf", "open pdf", "secure document", "click here to view", "click to view", "sign in to view", "sign in to access", "verify your account",
    "confirm your account", "update your account", "account will be", "has been suspended", "download document", "view online", "visualizza documento",
    "ver documento", "abrir documento", "dokument anzeigen", "afficher le document", "view invoice", "pending document", "documento compartido",
    // Account locked / verify, in the languages lures arrive in.
    "vérifier", "vérification", "verificar", "verificación", "verifizieren", "überprüfen", "verifica", "verificação", "ellenőrzés",
    "confirmer", "confirmar", "bestätigen", "suspendu", "suspendida", "suspensa", "gesperrt", "bloccato", "bloqueada", "letiltottuk",
    "débloquer", "desbloquear", "entsperren", "sbloccare", "feloldás", "temporarily disabled", "temporarily locked", "unusual activity",
];

/// Names callback scams borrow: security software, tech support, payments.
const CALLBACK_BRANDS: &[&str] = &[
    "Norton", "McAfee", "Avast", "Geek Squad", "PayPal", "Microsoft", "Windows Defender", "Apple", "Amazon", "Coinbase", "Malwarebytes", "Kaspersky", "Bitdefender",
];

/// Callback scams: a charge you did not make, or a renewal to cancel, and a
/// number to call (EN, FR, ES, DE, IT, PT, HU).
const CALLBACK: &[&str] = &[
    "if you did not", "if you didn't", "did not authorize", "didn't authorize", "not authorize", "cancel", "refund", "dispute", "renewal", "auto-renew",
    "annuler", "annulation", "remboursement", "renouvellement", "cancelar", "cancelación", "reembolso", "renovación", "stornieren", "kündigen",
    "rückerstattung", "verlängerung", "annullare", "rimborso", "rinnovo", "reembolso", "renovação", "lemondás", "visszatérítés",
];

fn run(argv: &[&str], work: &str, out: &mut Vec<(Ind, String)>) -> Option<Vec<u8>> {
    // zbarimg reads images through ImageMagick, which probes for a local
    // (Unix) socket: allowed, like for LibreOffice. The network stays denied.
    let r = monitor::run(argv, work, &Opts { allow_unix: argv[0].ends_with("zbarimg"), quiet_netlink: true, ..Opts::new(Net::Deny, Duration::from_secs(60)) });
    out.extend(r.events);
    r.stdout
}

fn host(url: &str) -> String {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let h = rest.split(['/', '?', '#']).next().unwrap_or("").rsplit('@').next().unwrap_or("");
    h.split(':').next().unwrap_or("").trim_end_matches('.').to_ascii_lowercase()
}

fn on(host: &str, domain: &str) -> bool {
    host == domain || host.ends_with(&format!(".{domain}"))
}

/// A phone number as callback scams print them: +1 (844) 555-0199, 1-800-...
fn has_phone(text: &str) -> bool {
    let digits_runs = text.split(|c: char| !(c.is_ascii_digit() || " ()+-.".contains(c)));
    digits_runs.into_iter().any(|r| {
        let d: String = r.chars().filter(|c| c.is_ascii_digit()).collect();
        (10..=13).contains(&d.len()) && r.trim().len() <= 20
    })
}

fn contains_word(hay: &str, needle: &str) -> bool {
    let n = needle.to_ascii_lowercase();
    hay.match_indices(&n).any(|(i, _)| {
        let before = hay[..i].chars().next_back().map_or(true, |c| !c.is_alphanumeric());
        let after = hay[i + n.len()..].chars().next().map_or(true, |c| !c.is_alphanumeric());
        before && after
    })
}

/// `links`: web links the document carries (from triage). `pages`: page count.
pub fn check(pdf: &str, work: &str, links: &[String], pages: u32) -> Vec<(Ind, String)> {
    let mut out = Vec::new();
    let dir = format!("{}/lure", crate::yara::SCRATCH);
    let _ = std::fs::remove_dir_all(&dir);
    if std::fs::create_dir_all(&dir).is_err() || std::os::unix::fs::chown(&dir, Some(monitor::RENDER_UID), Some(monitor::RENDER_GID)).is_err() {
        return out;
    }

    // QR codes on the first pages: their links are links like any other.
    // PGM: read by zbarimg (via ImageMagick) without extra image modules.
    let pattern = format!("{dir}/p%d.pgm");
    let _ = run(&["/usr/bin/mutool", "draw", "-q", "-r", "120", "-o", &pattern, pdf, PAGES], work, &mut out);
    let mut pngs: Vec<String> = std::fs::read_dir(&dir).map(|rd| rd.flatten().map(|e| e.path().display().to_string()).filter(|p| p.ends_with(".pgm")).collect()).unwrap_or_default();
    pngs.sort();
    let mut qr_links: Vec<String> = Vec::new();
    for png in &pngs {
        let page = png.rsplit("/p").next().and_then(|n| n.strip_suffix(".pgm")).unwrap_or("?").to_string();
        if let Some(stdout) = run(&["/usr/bin/zbarimg", "-q", "--raw", "-Sdisable", "-Sqrcode.enable", png], work, &mut out) {
            for line in String::from_utf8_lossy(&stdout).lines().take(8) {
                let t: String = line.trim().chars().filter(|c| !c.is_control()).take(300).collect();
                if t.is_empty() || qr_links.contains(&t) || qr_links.len() >= 10 {
                    continue;
                }
                out.push((Ind::QrLink, format!("page {page}: {t}")));
                qr_links.push(t);
            }
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    crate::log(&format!("phishing check: {} page image(s), {} QR code(s)", pngs.len(), qr_links.len()));

    // The wording of the first pages.
    let text = run(&["/usr/bin/mutool", "draw", "-q", "-F", "txt", "-o", "-", pdf, PAGES], work, &mut out).unwrap_or_default();
    let text = String::from_utf8_lossy(&text[..text.len().min(200_000)]).to_lowercase();
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    // "a Microsoft Word document" names software, not a login page.
    let mut branded = text.clone();
    for product in ["microsoft word", "microsoft excel", "microsoft powerpoint", "microsoft office word", "adobe acrobat reader dc is", "adobe reader is"] {
        branded = branded.replace(product, " ");
    }
    let brands: Vec<&(&str, &[&str])> = BRANDS.iter().filter(|(b, _)| contains_word(&branded, b)).collect();
    if brands.is_empty() {
        return out;
    }

    // Callback scam: a brand, a charge you did not make, a number to call.
    let callback = CALLBACK.iter().any(|p| text.contains(*p));
    let words = text.split(' ').count();
    if let Some(b) = CALLBACK_BRANDS.iter().find(|b| contains_word(&branded, b)) {
        if callback && has_phone(&text) && pages <= 2 && words < 600 {
            out.push((Ind::PhishText, format!("callback scam wording: uses the {b} name, a charge or renewal to cancel and a phone number to call")));
        }
    }

    // A short document that borrows a brand and asks for a click, while
    // its links (or QR codes) all go somewhere that brand does not own.
    let web: Vec<String> = links.iter().chain(&qr_links).filter(|l| l.to_ascii_lowercase().starts_with("http")).cloned().collect();
    // A page of a few lines is all lure: the brand and an off-brand link suffice.
    let asks = ACTION.iter().any(|a| text.contains(a)) || words < 250;
    if asks && pages <= 3 && !web.is_empty() && web.len() <= 10 {
        for (b, domains) in &brands {
            if web.iter().all(|u| !domains.iter().any(|d| on(&host(u), d))) {
                let name = b.trim_start_matches("© ").trim_end_matches(" ©").trim_end_matches(" Platforms");
                out.push((Ind::PhishText, format!("uses the {name} name and asks you to open or verify something, but its link goes to {}", host(&web[0]))));
                break;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn phones_and_words() {
        assert!(has_phone("call +1 (844) 555-0199 now"));
        assert!(has_phone("1-800-555-0123"));
        assert!(!has_phone("invoice 2026 total 1,234.56"));
        assert!(contains_word("sign in with your microsoft account", "microsoft"));
        assert!(!contains_word("microsoftish", "microsoft"));
        assert_eq!(host("https://user@Login.Example.com:8443/x?y"), "login.example.com");
        assert!(on("accounts.microsoft.com", "microsoft.com") && !on("microsoft.com.evil.io", "microsoft.com"));
    }
}
