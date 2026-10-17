#!/bin/sh
# Brings airlock's VM up to date. Stale renderers are the realistic risk, so:
#  - guest packages (MuPDF, LibreOffice, ...) are rebuilt with Alpine's
#    current security fixes, every time;
#  - the guest kernel moves to the newest 6.1 LTS release (checksums signed
#    by kernel.org, verified with GPG), Firecracker to its newest release,
#    and the Alpine base to its newest point release (published checksums).
# The working version is kept aside; the full regression suite must pass,
# otherwise it is restored untouched. On success an installed copy
# (scripts/install.sh) is updated too.
#
#   scripts/update.sh            update
#   scripts/update.sh --check    only show what is out of date
#   scripts/update.sh --rollback go back to the version before the last update
set -eu
cd "$(dirname "$0")/.."
MODE=update
case "${1:-}" in
    "") ;;
    --check) MODE=check ;;
    --rollback) MODE=rollback ;;
    *) echo "usage: $0 [--check|--rollback]" >&2; exit 2 ;;
esac
PREV=build/previous
LOG=build/update.log
die() { echo "error: $*" >&2; exit 1; }
# Pins are plain "NAME=value" lines (not e.g. "NAME=$NAME cmd").
pin() { sed -n "s/^$1=\([A-Za-z0-9.]*\)\$/\1/p" scripts/bootstrap.sh | head -1; }
setpin() { sed -i "s|^$1=[A-Za-z0-9.]*\$|$1=$2|" scripts/bootstrap.sh; }
installed() { [ -d "$HOME/.local/lib/airlock" ] && [ -x "$HOME/.local/bin/airlock" ]; }

restore() {
    [ -f "$PREV/bootstrap.sh" ] || die "nothing to roll back to"
    cp "$PREV/bootstrap.sh" scripts/bootstrap.sh
    cp "$PREV/firecracker" vendor/bin/firecracker
    cp "$PREV/vmlinux-airlock" vendor/bin/vmlinux-airlock
    cp --reflink=auto --sparse=always "$PREV/rootfs.ext4" build/rootfs.ext4
    cp "$PREV/rootfs.info" build/rootfs.info 2>/dev/null || true
    if installed; then scripts/install.sh >/dev/null 2>&1; fi
}

if [ "$MODE" = rollback ]; then
    restore
    echo "rolled back to the version from before the last update"
    exit 0
fi

# --- what is the newest of everything? ----------------------------------------
echo "==> Checking upstream versions"
KV=$(curl -fsS -m 30 https://www.kernel.org/releases.json | python3 -I -c '
import json, sys
v = [r["version"] for r in json.load(sys.stdin)["releases"] if r["version"].startswith("6.1.")]
print(v[0] if v else "")')
FCV=$(curl -fsS -m 30 https://api.github.com/repos/firecracker-microvm/firecracker/releases/latest | python3 -I -c 'import json, sys; print(json.load(sys.stdin)["tag_name"])')
AV=$(curl -fsS -m 30 "https://dl-cdn.alpinelinux.org/alpine/v$(pin ALPINE_VERSION | cut -d. -f1,2)/releases/x86_64/latest-releases.yaml" |
    sed -n 's/^ *file: alpine-minirootfs-\(.*\)-x86_64.tar.gz$/\1/p' | head -1)
STABLE=$(curl -fsS -m 30 https://alpinelinux.org/releases.json | python3 -I -c 'import json, sys; print(json.load(sys.stdin)["latest_stable"].lstrip("v"))' || true)
[ -n "$KV" ] && [ -n "$FCV" ] && [ -n "$AV" ] || die "could not read upstream versions"

changes=0
show() { # name current latest
    if [ "$2" = "$3" ]; then echo "   $1: $2 (newest)"; else echo "   $1: $2 -> $3"; changes=$((changes + 1)); fi
}
show "guest kernel (6.1 LTS)" "$(pin KERNEL_VERSION)" "$KV"
show "Firecracker" "$(pin FC_VERSION)" "$FCV"
show "Alpine base" "$(pin ALPINE_VERSION)" "$AV"
echo "   guest packages: rebuilt with current security fixes on every update"
case "$(pin ALPINE_VERSION)" in
    "$STABLE".*|"") ;;
    *) echo "   note: Alpine $STABLE is out; moving branch is a manual step (ALPINE_VERSION in scripts/bootstrap.sh)" ;;
esac
host/target/release/airlock doctor 2>&1 | awk '/guest image (built|is)|image age/ {print; keep = /warn/; next} keep {print; keep = 0}' 
[ "$MODE" = check ] && exit 0

# --- verify new inputs before touching anything -------------------------------
if [ "$KV" != "$(pin KERNEL_VERSION)" ]; then
    echo "==> Verifying kernel $KV (kernel.org signed checksums)"
    command -v gpg >/dev/null || die "gpg is needed to verify kernel releases"
    G=build/gnupg && rm -rf $G && mkdir -m 700 -p $G
    # Keys fetched by WKD from kernel.org into a private keyring.
    GNUPGHOME=$G gpg -q --auto-key-locate wkd --locate-keys torvalds@kernel.org gregkh@kernel.org >/dev/null 2>&1 || die "could not fetch kernel.org signing keys"
    curl -fsS -m 60 -o build/sha256sums.asc https://cdn.kernel.org/pub/linux/kernel/v6.x/sha256sums.asc
    GNUPGHOME=$G gpg -q --verify build/sha256sums.asc 2>/dev/null || die "kernel.org checksum list: bad signature"
    KSHA=$(awk -v f="linux-$KV.tar.xz" '$2 == f {print $1}' build/sha256sums.asc)
    [ -n "$KSHA" ] || die "no signed checksum for linux-$KV.tar.xz"
fi
if [ "$FCV" != "$(pin FC_VERSION)" ]; then
    echo "==> Firecracker $FCV (published checksum)"
    FSHA=$(curl -fsSL -m 60 "https://github.com/firecracker-microvm/firecracker/releases/download/$FCV/firecracker-$FCV-x86_64.tgz.sha256.txt" | awk '{print $1}')
    CSHA=$(curl -fsSL -m 60 "https://raw.githubusercontent.com/firecracker-microvm/firecracker/$FCV/resources/guest_configs/microvm-kernel-ci-x86_64-6.1.config" | sha256sum | awk '{print $1}')
    [ ${#FSHA} = 64 ] || die "no checksum published for Firecracker $FCV"
fi
if [ "$AV" != "$(pin ALPINE_VERSION)" ]; then
    echo "==> Alpine $AV (published checksum)"
    ASHA=$(curl -fsS -m 30 "https://dl-cdn.alpinelinux.org/alpine/v$(echo "$AV" | cut -d. -f1,2)/releases/x86_64/latest-releases.yaml" |
        awk -v f="alpine-minirootfs-$AV-x86_64.tar.gz" '$1 == "file:" {hit = ($2 == f)} hit && $1 == "sha256:" {print $2; exit}')
    [ ${#ASHA} = 64 ] || die "no checksum published for Alpine $AV"
fi

# --- keep the working version, then build and test the new one ---------------
echo "==> Keeping the current version in $PREV"
rm -rf "$PREV" && mkdir -p "$PREV"
cp scripts/bootstrap.sh vendor/bin/firecracker vendor/bin/vmlinux-airlock "$PREV/"
cp --reflink=auto --sparse=always build/rootfs.ext4 "$PREV/rootfs.ext4"
cp build/rootfs.info "$PREV/rootfs.info" 2>/dev/null || true

[ -z "${KSHA:-}" ] || { setpin KERNEL_VERSION "$KV"; setpin KERNEL_SHA256 "$KSHA"; }
[ -z "${FSHA:-}" ] || { setpin FC_VERSION "$FCV"; setpin FC_SHA256 "$FSHA"; setpin FC_CONFIG_SHA256 "$CSHA"; }
[ -z "${ASHA:-}" ] || { setpin ALPINE_VERSION "$AV"; setpin ALPINE_SHA256 "$ASHA"; }

echo "==> Rebuilding and running the regression suite (log: $LOG)"
if ! scripts/bootstrap.sh --tests >"$LOG" 2>&1; then
    restore
    tail -15 "$LOG" >&2
    die "the new version failed its checks; the previous version is back in place (full log: $LOG)"
fi

echo "==> Updated"
if [ -f "$PREV/rootfs.info" ]; then
    # Renderers and the parts an exploit would go through.
    for p in mupdf-tools libreoffice-common quickjs python3 py3-oletools musl; do
        old=$(grep "^$p-[0-9]" "$PREV/rootfs.info" | head -1)
        new=$(grep "^$p-[0-9]" build/rootfs.info | head -1)
        [ "$old" = "$new" ] || echo "   $old -> $new"
    done
    n=$(cat "$PREV/rootfs.info" build/rootfs.info | grep -v '^built' | sort | uniq -u | sed 's/-[0-9].*//' | sort -u | wc -l)
    echo "   $n guest package(s) changed in total"
fi
[ "$changes" = 0 ] || echo "   pins in scripts/bootstrap.sh changed — commit them"
if installed; then
    scripts/install.sh >/dev/null 2>&1 && echo "   installed copy updated"
fi
echo "   undo: $0 --rollback"
