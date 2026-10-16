#!/bin/sh
# Mozilla pdf.js's test PDFs (harmless but weird: malformed files, crashers,
# forms with JavaScript), pinned to a commit. ~980 files, ~70 MB.
# Then: tests/corpus-run.sh testdata/pdfjs   (stability + false alarms)
set -eu
cd "$(dirname "$0")/.."
REV=b3116c7e5f8a35027642d0061dfaaa6e9a671c36
mkdir -p testdata/pdfjs build
curl -fsSL "https://api.github.com/repos/mozilla/pdf.js/git/trees/$REV?recursive=1" | python3 -I -c '
import json, sys
for e in json.load(sys.stdin)["tree"]:
    p = e["path"]
    if p.startswith("test/pdfs/") and p.endswith(".pdf") and e["size"] <= 1_500_000 and "#" not in p:
        print(p)' > build/pdfjs-list.txt
xargs -P 8 -I{} sh -c 'f=testdata/pdfjs/$(basename "{}"); [ -s "$f" ] || curl -fsSL -o "$f" "https://raw.githubusercontent.com/mozilla/pdf.js/'"$REV"'/{}"' < build/pdfjs-list.txt
echo "$(ls testdata/pdfjs | wc -l) PDFs in testdata/pdfjs"
