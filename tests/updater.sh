#!/bin/sh
# The in-app updater, end to end, without GitHub: an "old" AppImage that
# looks for updates on a local server finds a newer, signed one there,
# downloads it, checks the signature and replaces itself. Then a tampered
# update (a valid file with someone else's signature) must be refused and
# leave the AppImage untouched.
#
#   tests/updater.sh        (about 15 minutes: two AppImage builds)
#
# Needs: the update key (~/.config/airlock/updater.key), sway + grim
# (headless, like the app screenshots), python3.
set -eu
cd "$(dirname "$0")/.."
T=$PWD/build/updater-test
PORT=${AIRLOCK_TEST_PORT:-8765}
rm -rf "$T"
mkdir -p "$T/server" "$T/home"
fail() { echo "FAIL $*"; exit 1; }

# The old version: 0.1.0, asking the local server instead of GitHub.
cat > "$T/old.json" <<EOF
{"plugins":{"updater":{"endpoints":["http://127.0.0.1:$PORT/latest.json"],"dangerousInsecureTransportProtocol":true}}}
EOF
AIRLOCK_VERSION=0.1.0-updatertest AIRLOCK_EXTRA_CONFIG=$T/old.json scripts/appimage.sh > "$T/build-old.log" 2>&1 || fail "old build (see $T/build-old.log)"
cp dist/airlock-0.1.0-updatertest-x86_64.AppImage "$T/airlock.AppImage"
rm -f dist/airlock-0.1.0-updatertest-x86_64.AppImage
chmod +x "$T/airlock.AppImage"
echo "ok   old version built (0.1.0)"

# The new version: 0.1.1, signed like a real release, served locally.
printf '{"version":"0.1.1"}' > "$T/new.json"
AIRLOCK_VERSION=0.1.1 AIRLOCK_LINUX_ONLY=1 AIRLOCK_EXTRA_CONFIG=$T/new.json AIRLOCK_RELEASE_URL=http://127.0.0.1:$PORT AIRLOCK_NOTES="updater test" \
    scripts/release.sh > "$T/build-new.log" 2>&1 || fail "new build (see $T/build-new.log)"
cp dist/release/v0.1.1/* "$T/server/"
rm -rf dist/release/v0.1.1 dist/airlock-0.1.1-x86_64.AppImage dist/airlock-0.1.1-x86_64.AppImage.sig
echo "ok   new version built and signed (0.1.1)"

(cd "$T/server" && exec python3 -m http.server "$PORT" --bind 127.0.0.1) > "$T/server.log" 2>&1 &
SERVER=$!
trap 'kill $SERVER 2>/dev/null' EXIT
sleep 1

# Runs the installed AppImage headless with a test home; it checks for an
# update and installs it (demo step "appupdate").
run_old() {
    conf=$T/sway.conf
    printf 'output HEADLESS-1 resolution 1200x800\nexec env HOME=%s XDG_CONFIG_HOME=%s/.config XDG_DATA_HOME=%s/.local/share XDG_STATE_HOME=%s/.local/state AIRLOCK_DEMO="wait=3000;appupdate;wait=1000" %s > %s/app.log 2>&1\n' \
        "$T/home" "$T/home" "$T/home" "$T/home" "$T/airlock.AppImage" "$T" > "$conf"
    env -u WAYLAND_DISPLAY -u DISPLAY WLR_BACKENDS=headless WLR_LIBINPUT_NO_DEVICES=1 WLR_RENDERER=pixman sway -c "$conf" > "$T/sway.log" 2>&1 &
    sp=$!
    i=0
    while [ $i -lt 240 ]; do
        grep -qE 'app update(: .* installed| failed| test: none)' "$T/home/.local/state/airlock/app.log" 2>/dev/null && break
        i=$((i+1)); sleep 1
    done
    kill $sp 2>/dev/null; wait $sp 2>/dev/null || true
    pkill -f "$T/airlock.AppImage" 2>/dev/null || true
}

# 1. A tampered update: the new file, but signed by a different key.
before=$(sha256sum "$T/airlock.AppImage" | cut -d' ' -f1)
cp "$T/server/latest.json" "$T/latest.good.json"
mkdir -p "$T/otherkey"
PATH=$HOME/.cargo/bin:$PATH cargo tauri signer generate --ci -p "" -w "$T/otherkey/k" > /dev/null 2>&1
PATH=$HOME/.cargo/bin:$PATH cargo tauri signer sign -f "$T/otherkey/k" -p "" "$T/server/airlock-0.1.1-x86_64.AppImage" > /dev/null 2>&1
python3 -I - "$T/server" <<'EOF'
import json, os, sys
d = sys.argv[1]
j = json.load(open(os.path.join(d, "latest.json")))
j["platforms"]["linux-x86_64"]["signature"] = open(os.path.join(d, "airlock-0.1.1-x86_64.AppImage.sig")).read().strip()
json.dump(j, open(os.path.join(d, "latest.json"), "w"))
EOF
run_old
after=$(sha256sum "$T/airlock.AppImage" | cut -d' ' -f1)
grep -q 'app update failed' "$T/home/.local/state/airlock/app.log" || fail "tampered update: no refusal logged ($(tail -2 "$T/home/.local/state/airlock/app.log" 2>/dev/null))"
[ "$before" = "$after" ] || fail "tampered update: the AppImage was changed"
echo "ok   tampered update refused, AppImage unchanged ($(grep 'app update failed' "$T/home/.local/state/airlock/app.log" | tail -1 | cut -d' ' -f4- | cut -c1-80))"

# 2. The real update.
cp "$T/latest.good.json" "$T/server/latest.json"
cp "$T/server/airlock-0.1.1-x86_64.AppImage" "$T/new.AppImage.copy"
rm -f "$T/home/.local/state/airlock/app.log"
# The server's AppImage is the signed original again (sign rewrote the .sig only).
run_old
grep -q 'app update: 0.1.1 installed' "$T/home/.local/state/airlock/app.log" || fail "update: not installed ($(tail -3 "$T/home/.local/state/airlock/app.log" 2>/dev/null | tr '\n' ' '))"
cmp -s "$T/airlock.AppImage" "$T/new.AppImage.copy" || fail "update: the AppImage is not the new version"
[ -x "$T/airlock.AppImage" ] || fail "update: the new AppImage is not executable"
echo "ok   update installed in place: the AppImage is now 0.1.1, executable, signature checked"
echo "UPDATER TEST PASSED"
