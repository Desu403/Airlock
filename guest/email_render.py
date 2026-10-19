"""E-mail messages (.eml) inside the VM, read with Python's standard library.

    python3 -I email_render.py page IN OUT.xhtml     the readable page
    python3 -I email_render.py extract IN N OUT      attachment N, as a file

`page` also prints lines for the agent: "@@ATT <n> <size> <name>" per
attachment and "@@LINK <url>" per web address in the message.
"""

import email
import email.policy
import html
import re
import sys
from html.parser import HTMLParser


class Visible(HTMLParser):
    """The text a reader sees in an HTML body, and its link targets."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text, self.links, self.hidden = [], [], 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "head", "title"):
            self.hidden += 1
        elif tag in ("br", "p", "div", "tr", "li", "table", "h1", "h2", "h3"):
            self.text.append("\n")
        if tag == "a":
            href = dict(attrs).get("href") or ""
            if href.startswith(("http://", "https://")):
                self.links.append(href)

    def handle_endtag(self, tag):
        if tag in ("script", "style", "head", "title") and self.hidden:
            self.hidden -= 1

    def handle_data(self, data):
        if not self.hidden:
            self.text.append(data)


def parse(path):
    with open(path, "rb") as f:
        return email.message_from_binary_file(f, policy=email.policy.default)


def attachments(msg):
    return [p for p in msg.iter_attachments()]


def body(msg):
    """(plain text, links) of the message's main body."""
    part = msg.get_body(preferencelist=("plain", "html"))
    if part is None:
        return "", []
    content = part.get_content()
    if part.get_content_type() == "text/html":
        v = Visible()
        v.feed(content)
        text = re.sub(r"\n\s*\n+", "\n\n", "".join(v.text)).strip()
        return text, v.links
    return content.strip(), []


def page(src, out):
    msg = parse(src)
    text, links = body(msg)
    links += re.findall(r"https?://[^\s<>\"')]+", text)
    seen = []
    for u in links:
        if u not in seen:
            seen.append(u)
            print(f"@@LINK {u[:500]}")
    rows = []
    for i, a in enumerate(attachments(msg)):
        name = a.get_filename() or f"attachment-{i + 1}"
        size = len(a.get_payload(decode=True) or b"")
        print(f"@@ATT {i} {size} {name}")
        rows.append(f"<tr><td>{html.escape(name)}</td><td class='s'>{size:,} bytes</td></tr>")
    head = "".join(
        f"<tr><th>{k}</th><td>{html.escape(str(msg.get(k, '')))}</td></tr>"
        for k in ("From", "To", "Cc", "Reply-To", "Date", "Subject") if msg.get(k))
    files = f"<h2>Attachments</h2><table>{''.join(rows)}</table>" if rows else ""
    paras = "".join(f"<p>{html.escape(p)}</p>" for p in text[:200000].split("\n"))
    css = """html, body { background: #0b1114; } body { margin: 0; color: #d8e2e4; font-family: "DejaVu Sans", sans-serif; font-size: 9.5pt; }
table { border-collapse: collapse; margin-bottom: 12pt; } th { text-align: left; color: #7f9a9b; padding: 2pt 10pt 2pt 0; font-weight: normal; vertical-align: top; }
td { padding: 2pt 0; } td.s { color: #7f9a9b; padding-left: 12pt; } h2 { font-size: 10pt; color: #fff; margin: 14pt 0 4pt; }
p { margin: 0 0 4pt; } .rule { border-top: 1px solid #1a2a2e; margin: 6pt 0 12pt; }"""
    with open(out, "w", encoding="utf-8") as f:
        f.write('<?xml version="1.0" encoding="utf-8"?>\n<html xmlns="http://www.w3.org/1999/xhtml"><head><title>E-mail</title>'
                f"<style>{css}</style></head><body><table>{head}</table>{files}<div class='rule'></div>{paras}</body></html>\n")


def extract(src, n, out):
    part = attachments(parse(src))[int(n)]
    with open(out, "wb") as f:
        f.write(part.get_payload(decode=True) or b"")


if __name__ == "__main__":
    if sys.argv[1] == "page":
        page(sys.argv[2], sys.argv[3])
    elif sys.argv[1] == "extract":
        extract(sys.argv[2], sys.argv[3], sys.argv[4])
