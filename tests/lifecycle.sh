#!/bin/sh
# The whole life of an install, as a new user's computer sees it, in an
# empty home folder: first-time setup, opening every kind of file, the daily
# update check, disk use after each step, uninstall. Uses the AppImage's own
# bundled kit and CLI (dist/), never the source tree.
#
#   tests/lifecycle.sh [AppImage]      (about 20 minutes; needs a built AppImage)
set -eu
cd "$(dirname "$0")/.."
IMG=$(realpath "${1:-dist/airlock-0.1.0-x86_64.AppImage}")
H=${LIFECYCLE_HOME:-/mnt/storage/airlock-lifecycle}
rm -rf "$H"; mkdir -p "$H"
export HOME=$H XDG_CONFIG_HOME=$H/.config XDG_DATA_HOME=$H/.local/share XDG_STATE_HOME=$H/.local/state XDG_CACHE_HOME=$H/.cache
LIB=$H/.local/lib/airlock
fail=0
ok()  { echo "ok   $*"; }
bad() { echo "FAIL $*"; fail=1; }
size() { du -sm "$1" 2>/dev/null | cut -f1; }

# The AppImage's contents: its kit (setup files) and bundled CLI.
( cd "$H" && "$IMG" --appimage-extract >/dev/null )
APP=$H/squashfs-root
KIT=$APP/usr/lib/airlock/kit
CLI=$APP/usr/lib/airlock/bin/airlock
[ -x "$CLI" ] && ok "AppImage carries its CLI" || bad "no CLI in the AppImage"

echo "== first-time setup (build) =="
start=$(date +%s)
if AIRLOCK_LIB=$LIB AIRLOCK_SINKHOLE=$APP/usr/lib/airlock/bin/sinkhole sh "$KIT/scripts/setup.sh" build > "$H/setup.log" 2>&1; then
    ok "setup built the viewer in $(( $(date +%s) - start ))s"
else
    bad "setup failed: $(tail -3 "$H/setup.log")"
fi
for f in rootfs.ext4 vmlinux firecracker sinkhole known-malware.bin urlhaus.txt clamav.ext4; do [ -f "$LIB/$f" ] || bad "missing $f after setup"; done
mb=$(size "$H/.local/lib/airlock")
echo "     disk after setup: ${mb} MB (viewer $(size "$LIB/rootfs.ext4") MB, kit $(size "$LIB/kit") MB)"
[ "$mb" -lt 3000 ] && ok "setup leaves under 3 GB" || bad "setup leaves ${mb} MB"
for left in build/guestroot build/guestroot.tar build/rootfs.ext4 build/kernel; do [ ! -e "$LIB/kit/$left" ] || bad "setup left kit/$left behind"; done

echo "== opening every kind of file (the AppImage's CLI, the installed viewer) =="
T=$H/files; mkdir -p "$T/z"
cp testdata/clean.pdf "$T/doc.pdf"; cp tests/smoke/90bb8251b18c9f94.docx "$T/doc.docx"; cp app/icons/128x128.png "$T/pic.png"
cp guest/code_render.py "$T/code.py"; cp testdata/clean.pdf "$T/z/inner.pdf"; ( cd "$T/z" && 7z a -tzip ../box.zip inner.pdf >/dev/null )
for f in doc.pdf doc.docx pic.png code.py box.zip; do
    if AIRLOCK_LIB=$LIB timeout 120 "$CLI" view "$T/$f" --out "$T/out-$f" > "$T/$f.log" 2>&1 && [ -f "$T/out-$f/page-0001.png" ]; then ok "opens $f"; else bad "cannot open $f: $(tail -1 "$T/$f.log")"; fi
done
if AIRLOCK_LIB=$LIB timeout 300 "$CLI" analyze testdata/evil.pdf --out "$T/an" --report-only 2>&1 | grep -q 'MALICIOUS'; then ok "evil.pdf is caught"; else bad "evil.pdf not caught"; fi

echo "== the daily update check (status) =="
if ( cd "$LIB/kit" && AIRLOCK_CLI=$CLI sh scripts/update.sh --status > "$H/status.log" 2>&1 ); then ok "update check runs: $(grep -E '^available' "$H/status.log")"; else bad "update check failed: $(tail -2 "$H/status.log")"; fi
mb2=$(size "$H/.local/lib/airlock")
echo "     disk after the update check: ${mb2} MB"

echo "== a full update (what Update now does: rebuild, every test, install) =="
start=$(date +%s)
if ( cd "$LIB/kit" && AIRLOCK_CLI=$CLI sh scripts/update.sh > "$H/update.log" 2>&1 ); then
    ok "update ran and passed its tests in $(( $(date +%s) - start ))s"
else
    bad "update failed: $(tail -3 "$H/update.log")"
fi
if AIRLOCK_LIB=$LIB timeout 120 "$CLI" view "$T/doc.pdf" --out "$T/after-update" > "$T/after.log" 2>&1 && [ -f "$T/after-update/page-0001.png" ]; then ok "documents open after the update"; else bad "cannot open after the update: $(tail -1 "$T/after.log")"; fi
[ -d "$LIB/kit/build/previous" ] && ok "a rollback copy is kept" || bad "no rollback copy after the update"
for left in build/guestroot build/guestroot.tar build/rootfs.ext4 build/kernel; do [ ! -e "$LIB/kit/$left" ] || bad "the update left kit/$left behind"; done
mb3=$(size "$H/.local/lib/airlock")
echo "     disk after the update: ${mb3} MB (rollback copy $(size "$LIB/kit/build/previous") MB, kept a week)"

echo "== uninstall leftovers =="
rm -rf "$LIB" "$H/.local/share/applications/airlock.desktop"
[ ! -e "$LIB" ] && ok "viewer folder removed" || bad "viewer folder still there"

[ "$fail" = 0 ] && echo "LIFECYCLE PASSED" || echo "LIFECYCLE FAILED"
exit $fail
