#!/bin/sh
# The in-app updater on Windows, end to end, without GitHub: an "old"
# airlock installed on the test laptop finds a newer, signed installer on
# this computer, checks its signature and installs it; before that, the same
# installer with someone else's signature must be refused.
#
#   tests/updater-windows.sh user@windows-host     (about 40 minutes)
#
# Needs: the laptop reachable over SSH (key login), the update key, the
# Windows toolchain (scripts/windows.sh). The laptop downloads from a
# temporary web server on this computer (port 8765 on 127.0.0.1 only, through
# an SSH tunnel, only while the test runs).
set -eu
cd "$(dirname "$0")/.."
HOST=${1:-${AIRLOCK_WINDOWS_HOST:?usage: tests/updater-windows.sh user@windows-host}}
T=$PWD/build/updater-test-windows
PORT=${AIRLOCK_TEST_PORT:-8765}
# The laptop reaches this computer's test server through an SSH tunnel
# (its own 127.0.0.1:PORT): no firewall port has to be opened here.
ME=127.0.0.1
# AIRLOCK_TEST_REUSE=1: keep the installers of the last run (no rebuild).
[ "${AIRLOCK_TEST_REUSE:-}" = 1 ] || rm -rf "$T"
mkdir -p "$T/server"
fail() { echo "FAIL $*"; exit 1; }
ps() { # runs PowerShell code on the laptop
    printf '%s\n' "$1" > "$T/run.ps1"
    scp -q -o BatchMode=yes "$T/run.ps1" "$HOST:C:/airlock-test/run-updater.ps1" 2>/dev/null
    ssh -o BatchMode=yes "$HOST" "powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:/airlock-test/run-updater.ps1" 2>&1 | { grep -v -E 'post-quantum|store now|upgraded. See' || true; }
}
ssh -o BatchMode=yes -o ConnectTimeout=8 "$HOST" exit 2>/dev/null || fail "laptop $HOST not reachable"

# Old 0.1.0, asking this computer instead of GitHub; new 0.1.1, signed.
cat > "$T/old.json" <<EOF
{"plugins":{"updater":{"endpoints":["http://$ME:$PORT/latest.json"],"dangerousInsecureTransportProtocol":true}}}
EOF
if [ ! -f "$T/old-setup.exe" ]; then
    AIRLOCK_VERSION=0.1.0-updatertest AIRLOCK_EXTRA_CONFIG=$T/old.json scripts/windows.sh > "$T/build-old.log" 2>&1 || fail "old build (see $T/build-old.log)"
    mv dist/airlock-0.1.0-updatertest-windows-x64-setup.exe "$T/old-setup.exe"
fi
echo "ok   old installer built (0.1.0)"
printf '{"version":"0.1.1"}' > "$T/new.json"
if [ ! -f "$T/server/airlock-0.1.1-windows-x64-setup.exe.sig" ]; then
    TAURI_SIGNING_PRIVATE_KEY=$(cat "$HOME/.config/airlock/updater.key") TAURI_SIGNING_PRIVATE_KEY_PASSWORD="" \
        AIRLOCK_VERSION=0.1.1 AIRLOCK_EXTRA_CONFIG=$T/new.json scripts/windows.sh > "$T/build-new.log" 2>&1 || fail "new build (see $T/build-new.log)"
    mv dist/airlock-0.1.1-windows-x64-setup.exe dist/airlock-0.1.1-windows-x64-setup.exe.sig "$T/server/"
fi
echo "ok   new installer built and signed (0.1.1)"
latest() { # signature file -> latest.json
    python3 -I - "$T/server" "$1" "http://$ME:$PORT" <<'EOF'
import json, os, sys
d, sig, base = sys.argv[1:]
json.dump({"version": "0.1.1", "notes": "updater test", "pub_date": "2026-10-20T00:00:00Z",
           "platforms": {"windows-x86_64": {"signature": open(sig).read().strip(), "url": f"{base}/airlock-0.1.1-windows-x64-setup.exe"}}},
          open(os.path.join(d, "latest.json"), "w"))
EOF
}

(cd "$T/server" && exec python3 -m http.server "$PORT" --bind 127.0.0.1) > "$T/server.log" 2>&1 &
SERVER=$!
ssh -o BatchMode=yes -o ExitOnForwardFailure=yes -N -R "$PORT:127.0.0.1:$PORT" "$HOST" 2>/dev/null &
TUNNEL=$!
trap 'kill $SERVER $TUNNEL 2>/dev/null' EXIT
sleep 1

# Install the old version (silent, per user) on the laptop.
ps 'Get-Process airlock-app,qemu-system-x86_64 -ErrorAction SilentlyContinue | Stop-Process -Force' > /dev/null
scp -q -o BatchMode=yes "$T/old-setup.exe" "$HOST:C:/airlock-test/old-setup.exe" 2>/dev/null
ps '$p = Start-Process -PassThru -Wait C:\airlock-test\old-setup.exe -ArgumentList "/S"; "installer exit $($p.ExitCode)"' | grep -q 'installer exit 0' || fail "old install"
version() { ps '(Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\airlock -ErrorAction SilentlyContinue).DisplayVersion' | tr -d '\r' | tail -1; }
[ "$(version)" = "0.1.0" ] || fail "old version not installed ($(version))"
echo "ok   0.1.0 installed on the laptop"

# Runs the installed app on the laptop's desktop with the update step, and
# waits for its log to say how it went.
run_app() {
    ps 'Remove-Item "$env:LOCALAPPDATA\airlock\logs\app.log" -ErrorAction SilentlyContinue
$u = (Get-CimInstance Win32_ComputerSystem).UserName
$cmd = "set AIRLOCK_DEMO=wait=3000;appupdate;wait=1000&& start """" ""$env:LOCALAPPDATA\airlock\airlock-app.exe"""
$a = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c $cmd"
Register-ScheduledTask -TaskName airlock-updater-test -Action $a -User $u -RunLevel Limited -Force | Out-Null
Start-ScheduledTask -TaskName airlock-updater-test' > /dev/null
    i=0
    while [ $i -lt 60 ]; do
        sleep 5
        out=$(ps 'Get-Content "$env:LOCALAPPDATA\airlock\logs\app.log" -ErrorAction SilentlyContinue | Select-String "app update" | Select -Last 2')
        case $out in *"installed"*|*"failed"*|*"none found"*) break ;; esac
        # The updater closes airlock to run the installer: the new version is the sign.
        [ "$(version)" = "0.1.1" ] && break
        i=$((i+1))
    done
    echo "$out"
}

# 1. Tampered: the right installer, signed with a different key.
rm -rf "$T/otherkey"; mkdir -p "$T/otherkey"
PATH=$HOME/.cargo/bin:$PATH cargo tauri signer generate --ci -p "" -w "$T/otherkey/k" > /dev/null 2>&1
cp "$T/server/airlock-0.1.1-windows-x64-setup.exe" "$T/otherkey/setup.exe"
PATH=$HOME/.cargo/bin:$PATH cargo tauri signer sign -f "$T/otherkey/k" -p "" "$T/otherkey/setup.exe" > /dev/null 2>&1
latest "$T/otherkey/setup.exe.sig"
out=$(run_app)
# A broken download (the SSH tunnel) is not the check we want: once more.
case $out in *"decoding response body"*|*"error sending request"*) out=$(run_app) ;; esac
case $out in *"signature"*|*"different key"*) ;; *) fail "tampered update was not refused by its signature: $out" ;; esac
sleep 5
[ "$(version)" = "0.1.0" ] || fail "tampered update changed the installed version ($(version))"
echo "ok   tampered update refused, 0.1.0 still installed"

# 2. The real update.
latest "$T/server/airlock-0.1.1-windows-x64-setup.exe.sig"
out=$(run_app)
case $out in *"decoding response body"*|*"error sending request"*) out=$(run_app) ;; esac
# On Windows the updater closes airlock to run the installer, so the log
# shows the download only; the installed version is the proof.
case $out in *"downloading 0.1.1"*|*"installed"*) ;; *) fail "update did not start: $out" ;; esac
i=0
while [ "$(version)" != "0.1.1" ] && [ $i -lt 40 ]; do sleep 5; i=$((i+1)); done
[ "$(version)" = "0.1.1" ] || fail "installed version is $(version), not 0.1.1"
echo "ok   update installed: the laptop now has 0.1.1 (signature checked)"
ps 'Get-Process airlock-app -ErrorAction SilentlyContinue | Stop-Process -Force; Unregister-ScheduledTask -TaskName airlock-updater-test -Confirm:$false -ErrorAction SilentlyContinue; Remove-Item C:\airlock-test\old-setup.exe,C:\airlock-test\run-updater.ps1 -ErrorAction SilentlyContinue' > /dev/null
echo "WINDOWS UPDATER TEST PASSED"
