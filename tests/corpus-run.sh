#!/bin/sh
# Runs `airlock analyze` over every file in a directory (in parallel) and
# writes one line per file: verdict, exit status, seconds, name. For corpora
# of harmless-but-weird documents (pdf.js test PDFs, ...): checks stability
# and false alarms.
#
# Usage: tests/corpus-run.sh <dir> [out-dir] [jobs]
set -eu
[ $# -ge 1 ] || { echo "usage: $0 <dir> [out-dir] [jobs]" >&2; exit 2; }
ROOT=$(cd "$(dirname "$0")/.." && pwd)
SRC=$(cd "$1" && pwd)
OUT=${2:-$ROOT/build/corpus/$(basename "$SRC")}
JOBS=${3:-4}
mkdir -p "$OUT/logs"
: > "$OUT/results.tsv"
export AIRLOCK=$ROOT/host/target/release/airlock OUT

find "$SRC" -maxdepth 1 -type f -print0 | xargs -0 -P "$JOBS" -I{} sh -c '
    f=$1; n=$(basename "$f")
    t0=$(date +%s.%N)
    if "$AIRLOCK" analyze "$f" --out "$OUT/r/$n" >"$OUT/logs/$n.log" 2>&1; then rc=0; else rc=$?; fi
    secs=$(awk -v a="$t0" -v b="$(date +%s.%N)" "BEGIN {print b - a}")
    v=$(sed -n "s/^=== airlock report: \(.*\) ===\$/\1/p" "$OUT/logs/$n.log")
    printf "%s\t%s\t%.1f\t%s\n" "${v:-NO REPORT}" "$rc" "$secs" "$n" >> "$OUT/results.tsv"
    rm -rf "$OUT/r/$n"   # keep logs + report text, not the page images
' _ {}

echo "== $(wc -l < "$OUT/results.tsv") files =="
cut -f1 "$OUT/results.tsv" | sort | uniq -c | sort -rn
echo "non-zero exits: $(awk -F'\t' '$2 != 0' "$OUT/results.tsv" | wc -l)"
echo "results: $OUT/results.tsv"
