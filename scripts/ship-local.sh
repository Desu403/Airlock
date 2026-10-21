#!/bin/sh
# Ships a release that passed the gate to this computer's own airlock:
# installs dist/airlock-<version>-x86_64.AppImage as ~/Applications/airlock.AppImage
# (atomic swap), then updates the installed viewer through the AppImage's
# own update path (its kit + scripts/update.sh, as a user's app does), and
# checks that the installed copy analyzes a test file.
#
#   scripts/ship-local.sh GATE_SUMMARY
#
# GATE_SUMMARY: the gate's summary file; nothing is shipped unless it shows
# the suite, the lifecycle test and the bench all passed with 0 false alarms
# and 0 regressions.
set -eu
cd "$(dirname "$0")/.."
S=${1:?gate summary file}
grep -q '^suite exit=0' "$S" && grep -q '^ALL PASSED' "$S" || { echo "not shipped: regression suite did not pass"; exit 1; }
grep -q '^lifecycle exit=0' "$S" && grep -q 'LIFECYCLE PASSED' "$S" || { echo "not shipped: lifecycle test did not pass"; exit 1; }
if grep -q '^bench exit=' "$S"; then
    grep -q '^bench exit=0' "$S" && grep -q ' 0 FALSE ALARMS' "$S" && grep -q ' 0 REGRESSIONS' "$S" || { echo "not shipped: bench not clean"; exit 1; }
fi
VERSION=$(sed -n 's/^  "version": "\(.*\)",/\1/p' app/tauri.conf.json)
A=dist/airlock-$VERSION-x86_64.AppImage
[ -f "$A" ] || { echo "not shipped: $A missing"; exit 1; }
mkdir -p "$HOME/Applications"
cp "$A" "$HOME/Applications/.airlock-update.AppImage"
chmod +x "$HOME/Applications/.airlock-update.AppImage"
mv -f "$HOME/Applications/.airlock-update.AppImage" "$HOME/Applications/airlock.AppImage"
echo "installed $HOME/Applications/airlock.AppImage"

# The viewer, updated the way a user's install is: from the AppImage's kit.
M=${XDG_RUNTIME_DIR:-/tmp}/airlock-ship.$$
rm -rf "$M"
mkdir -p "$M"
trap 'rm -rf "$M"' EXIT
(cd "$M" && "$HOME/Applications/airlock.AppImage" --appimage-extract >/dev/null)
K=$M/squashfs-root/usr/lib/airlock/kit
L=$HOME/.local/lib/airlock
for d in guest guest-agent proto scripts tests; do
    rm -rf "$L/kit/$d"
    cp -r "$K/$d" "$L/kit/$d"
done
cp "$K/.kit-version" "$K/.vm-version" "$L/kit/"
(cd "$L/kit" && AIRLOCK_CLI=$M/squashfs-root/usr/lib/airlock/bin/airlock sh scripts/update.sh) > "$M/update.log" 2>&1 || { tail -20 "$M/update.log"; echo "viewer update FAILED (the update keeps the previous viewer)"; exit 1; }
tail -3 "$M/update.log"
v=$(AIRLOCK_LIB=$L "$M/squashfs-root/usr/lib/airlock/bin/airlock" analyze tests/smoke/cd1939be34ba0c8b.pdf --out "$M/check" --report-only 2>&1 | grep '=== airlock report' || true)
case $v in
    *"NO ACTIVE BEHAVIOUR OBSERVED"*) echo "installed copy checked: $v" ;;
    *) echo "installed copy check FAILED: ${v:-no report}"; exit 1 ;;
esac
