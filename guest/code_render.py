"""Source code and plain text as a syntax-coloured XHTML page, inside the VM.

    python3 -I code_render.py INPUT OUTPUT.xhtml [EXT] [dark|light]

MuPDF lays the XHTML out into PDF pages (mutool convert), so the pages carry
real text: search and the Text panel work as for any document. Line numbers
are a gutter of figure spaces and digits that the VM drops from the
extracted text, so copied or searched code has none.
The file is never run: Pygments only splits it into tokens.
"""

import html
import sys

from pygments import lex
from pygments.lexers import TextLexer, get_lexer_for_filename, guess_lexer
from pygments.token import Token
from pygments.util import ClassNotFound

MAX_BYTES = 4 * 1024 * 1024  # bigger text files are cut (noted at the end)
MAX_LINES = 20000
WRAP = 96  # an unbroken run this long gets a break point (U+200B)
# The line-number gutter: figure spaces (U+2007) pad it and end it, so the
# VM's text extraction can drop it exactly (live.rs strip_gutter).
FIG = "\u2007"
# MuPDF reports each character's colour but turns these spaces into plain
# ones: the gutter and the break points get colours of their own, and the
# VM drops characters in exactly these colours (live.rs, keep in sync).
GUTTER = {"dark": "#4d6267", "light": "#9aa1a9"}
BREAK = "#010203"

# Token colours, dark ("console", the app's look) and light ("paper", printing).
THEMES = {
    "dark": {
        "bg": "#0b1114", "fg": "#d8e2e4", "num": "#4d6267", "note": "#6c8a8f",
        Token.Keyword: "#c792ea", Token.Keyword.Constant: "#f78c6c", Token.Keyword.Type: "#ffcb6b",
        Token.Name.Builtin: "#82aaff", Token.Name.Function: "#82aaff", Token.Name.Class: "#ffcb6b",
        Token.Name.Decorator: "#c3e88d", Token.Name.Tag: "#f07178", Token.Name.Attribute: "#ffcb6b",
        Token.Name.Variable: "#f07178", Token.Name.Exception: "#ffcb6b",
        Token.String: "#c3e88d", Token.String.Escape: "#89ddff", Token.String.Doc: "#6c8a8f",
        Token.Number: "#f78c6c", Token.Operator: "#89ddff", Token.Punctuation: "#89ddff",
        Token.Comment: "#6c8a8f", Token.Comment.Preproc: "#89ddff",
        Token.Generic.Heading: "#82aaff", Token.Generic.Inserted: "#c3e88d", Token.Generic.Deleted: "#f07178",
        Token.Error: "#ff5370",
    },
    "light": {
        "bg": "#ffffff", "fg": "#1f2328", "num": "#9aa1a9", "note": "#6e7781",
        Token.Keyword: "#8250df", Token.Keyword.Constant: "#0550ae", Token.Keyword.Type: "#953800",
        Token.Name.Builtin: "#0550ae", Token.Name.Function: "#6639ba", Token.Name.Class: "#953800",
        Token.Name.Decorator: "#116329", Token.Name.Tag: "#116329", Token.Name.Attribute: "#0550ae",
        Token.Name.Variable: "#953800", Token.Name.Exception: "#953800",
        Token.String: "#0a3069", Token.String.Escape: "#0550ae", Token.String.Doc: "#6e7781",
        Token.Number: "#0550ae", Token.Operator: "#cf222e", Token.Punctuation: "#1f2328",
        Token.Comment: "#6e7781", Token.Comment.Preproc: "#cf222e",
        Token.Generic.Heading: "#0550ae", Token.Generic.Inserted: "#116329", Token.Generic.Deleted: "#82071e",
        Token.Error: "#cf222e",
    },
}


def colour(theme, ttype):
    while ttype is not None:
        if ttype in theme:
            return theme[ttype]
        ttype = ttype.parent
    return None


def decode(raw):
    for enc in ("utf-8", "utf-16"):
        try:
            if enc == "utf-16" and not raw.startswith((b"\xff\xfe", b"\xfe\xff")):
                continue
            return raw.decode(enc)
        except UnicodeDecodeError:
            pass
    return raw.decode("latin-1")


def pick_lexer(text, ext):
    if ext:
        try:
            return get_lexer_for_filename("file." + ext, stripnl=False, ensurenl=False)
        except ClassNotFound:
            pass
    try:
        lexer = guess_lexer(text[:20000], stripnl=False, ensurenl=False)
        # A weak guess on prose is worse than none.
        return lexer if lexer.analyse_text(text[:20000]) >= 0.3 else TextLexer(stripnl=False)
    except ClassNotFound:
        return TextLexer(stripnl=False)


def main():
    src, out = sys.argv[1], sys.argv[2]
    ext = sys.argv[3] if len(sys.argv) > 3 else ""
    theme = THEMES.get(sys.argv[4] if len(sys.argv) > 4 else "dark", THEMES["dark"])
    with open(src, "rb") as f:
        raw = f.read(MAX_BYTES + 1)
    cut = len(raw) > MAX_BYTES
    text = decode(raw[:MAX_BYTES]).replace("\r\n", "\n").replace("\r", "\n").expandtabs(4)
    lexer = pick_lexer(text, ext)

    lines, cur, run = [], [], 0
    for ttype, value in lex(text, lexer):
        parts = value.split("\n")
        for i, part in enumerate(parts):
            if i:
                lines.append("".join(cur))
                cur, run = [], 0
            if part:
                # MuPDF wraps only at spaces: give long runs break points.
                c = colour(theme, ttype) or theme["fg"]
                piece = []
                for ch in part:
                    run = 0 if ch == " " else run + 1
                    piece.append(ch)
                    if run >= WRAP:
                        cur.append(f'<span style="color:{c}">{html.escape("".join(piece), quote=False)}</span>')
                        cur.append(f'<span style="color:{BREAK}"> </span>')
                        piece, run = [], 0
                if piece:
                    cur.append(f'<span style="color:{c}">{html.escape("".join(piece), quote=False)}</span>')
    if cur or not lines:
        lines.append("".join(cur))
    if lines and lines[-1] == "" and len(lines) > 1:
        lines.pop()
    if len(lines) > MAX_LINES:
        lines, cut = lines[:MAX_LINES], True

    digits = len(str(len(lines)))
    num = theme["num"]
    body = "\n".join(
        f'<p><span style="color:{num}">{str(n).rjust(digits, FIG)}{FIG}</span>{line}</p>' for n, line in enumerate(lines, 1))
    note = f'<p class="cut">… the rest is not shown (longer than {MAX_LINES} lines or {MAX_BYTES // (1024 * 1024)} MB)</p>' if cut else ""
    indent = round((digits + 1) * 0.602 * 8.6 + 0.5, 1)
    title = html.escape(getattr(lexer, "name", "Text"))
    css = f"""
@page {{ margin: 28pt 24pt 28pt 18pt; }}
html, body {{ background: {theme["bg"]}; }}
body {{ margin: 0; color: {theme["fg"]}; font-family: "DejaVu Sans Mono", monospace; font-size: 8.6pt; line-height: 1.42; }}
p {{ margin: 0; white-space: pre-wrap; padding-left: {indent}pt; text-indent: -{indent}pt; }}
.cut {{ color: {theme["note"]}; margin-top: 10pt; }}
"""
    with open(out, "w", encoding="utf-8") as f:
        f.write('<?xml version="1.0" encoding="utf-8"?>\n<html xmlns="http://www.w3.org/1999/xhtml"><head>'
                f'<title>{title}</title><style>{css}</style></head><body>{body}{note}</body></html>\n')
    print(f"@@LANG {getattr(lexer, 'name', 'Text')}")


if __name__ == "__main__":
    main()
