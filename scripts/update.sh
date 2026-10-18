#!/bin/sh
# Brings airlock's VM up to date. Stale renderers are the realistic risk, so:
#  - guest packages (MuPDF, LibreOffice, ...) are rebuilt with Alpine's
#    current security fixes, every time;
#  - the guest kernel moves to the newest 6.1 LTS release (checksums signed
#    by kernel.org, verified with GPG), Firecracker to its newest release,
#    and the Alpine base to its newest point release (published checksums);
#  - the YARA malware signatures move to YARA-Forge's newest release (its
#    published SHA-256 digest).
# The working version is kept aside; the full regression suite must pass,
# otherwise it is restored untouched. On success an installed copy
# (scripts/install.sh) is updated too.
#
# Runs from a source checkout, or from the update kit that scripts/install.sh
# puts in <prefix>/lib/airlock/kit: then only official servers are needed
# (Alpine, kernel.org, Firecracker's releases) and no tools beyond what
# airlock itself needs; the build happens in a throwaway Alpine build root.
#
#   scripts/update.sh            update
#   scripts/update.sh --check    only show what is out of date
#   scripts/update.sh --rollback go back to the version before the last update
#   scripts/update.sh --status   machine-readable check for the app (key=value),
#                                also cached in build/update-status
set -eu
cd "$(dirname "$0")/.."
MODE=update
case "${1:-}" in
    "") ;;
    --check) MODE=check ;;
    --status) MODE=status ;;
    --rollback) MODE=rollback ;;
    *) echo "usage: $0 [--check|--status|--rollback]" >&2; exit 2 ;;
esac
PREV=build/previous
LOG=build/update.log
die() { echo "error: $*" >&2; exit 1; }
# Pins are plain "NAME=value" lines (not e.g. "NAME=$NAME cmd").
pin() { sed -n "s/^$1=\([A-Za-z0-9.]*\)\$/\1/p" scripts/bootstrap.sh | head -1; }
setpin() { sed -i "s|^$1=[A-Za-z0-9.]*\$|$1=$2|" scripts/bootstrap.sh; }
installed() { [ -d "$HOME/.local/lib/airlock" ] && [ -x "$HOME/.local/bin/airlock" ]; }
# put SRC DEST: replace atomically (running VMs keep their copy).
put() { cp --reflink=auto --sparse=always "$1" "$2.new" && mv -f "$2.new" "$2"; }

if [ -f .airlock-kit ]; then
    # Update kit inside an install: <prefix>/lib/airlock/kit.
    KIT=1
    LIB=$(cd .. && pwd)
    AIRLOCK=$(cd ../../.. && pwd)/bin/airlock
    ROOTFS=$LIB/rootfs.ext4
    INFO=$LIB/rootfs.info
else
    KIT=0
    AIRLOCK=host/target/release/airlock
    ROOTFS=build/rootfs.ext4
    INFO=build/rootfs.info
fi
# The AppImage carries its own CLI (not in <prefix>/bin).
[ -n "${AIRLOCK_CLI:-}" ] && AIRLOCK=$AIRLOCK_CLI
[ -x "$AIRLOCK" ] || die "airlock binary not found at $AIRLOCK"

# Kit: the new VM goes live only now, after it passed the regression suite.
deploy() {
    put vendor/bin/firecracker "$LIB/firecracker"
    put vendor/bin/vmlinux-airlock "$LIB/vmlinux"
    put build/rootfs.ext4 "$LIB/rootfs.ext4"
    put build/rootfs.info "$LIB/rootfs.info"
}

# Kit: drop the large build leftovers (the Alpine build root stays as a cache).
tidy() {
    rm -rf build/guestroot build/guestroot.tar build/rootfs.ext4 build/kernel build/tests vendor/dl/kernel/linux-*.tar.xz
}

restore() {
    [ -f "$PREV/bootstrap.sh" ] || die "nothing to roll back to"
    cp "$PREV/bootstrap.sh" scripts/bootstrap.sh
    cp "$PREV/firecracker" "$PREV/vmlinux-airlock" vendor/bin/
    cp "$PREV/vmlinux-airlock.stamp" vendor/bin/ 2>/dev/null || rm -f vendor/bin/vmlinux-airlock.stamp
    if [ "$KIT" = 1 ]; then
        put vendor/bin/firecracker "$LIB/firecracker"
        put vendor/bin/vmlinux-airlock "$LIB/vmlinux"
        put "$PREV/rootfs.ext4" "$LIB/rootfs.ext4"
        [ ! -f "$PREV/rootfs.info" ] || put "$PREV/rootfs.info" "$LIB/rootfs.info"
        tidy
    else
        put "$PREV/rootfs.ext4" build/rootfs.ext4
        [ ! -f "$PREV/rootfs.info" ] || cp "$PREV/rootfs.info" build/rootfs.info
        if installed; then scripts/install.sh >/dev/null 2>&1; fi
    fi
}

if [ "$MODE" = rollback ]; then
    restore
    echo "rolled back to the version from before the last update"
    exit 0
fi

# Guest packages with a newer version in Alpine's index: "name old new".
outdated_packages() {
    [ -f "$INFO" ] || return 0
    branch=v$(pin ALPINE_VERSION | cut -d. -f1,2)
    for repo in main community; do
        curl -fsS -m 120 "https://dl-cdn.alpinelinux.org/alpine/$branch/$repo/x86_64/APKINDEX.tar.gz" | python3 -I -c '
import io, sys, tarfile
idx = tarfile.open(fileobj=io.BytesIO(sys.stdin.buffer.read())).extractfile("APKINDEX").read().decode()
for block in idx.split("\n\n"):
    f = dict(l.split(":", 1) for l in block.splitlines() if ":" in l)
    if "P" in f and "V" in f:
        print(f["P"], f["V"])'
    done | python3 -I -c '
import sys
latest = dict(l.split() for l in sys.stdin if len(l.split()) == 2)
for line in open(sys.argv[1]):
    p = line.strip().rsplit("-", 2)
    if len(p) == 3 and p[0] in latest and latest[p[0]] != p[1] + "-" + p[2]:
        print(p[0], p[1] + "-" + p[2], latest[p[0]])' "$INFO"
}

# --- what is the newest of everything? ----------------------------------------
[ "$MODE" = status ] || echo "==> Checking upstream versions"
KV=$(curl -fsS -m 30 https://www.kernel.org/releases.json | python3 -I -c '
import json, sys
v = [r["version"] for r in json.load(sys.stdin)["releases"] if r["version"].startswith("6.1.")]
print(v[0] if v else "")')
FCV=$(curl -fsS -m 30 https://api.github.com/repos/firecracker-microvm/firecracker/releases/latest | python3 -I -c 'import json, sys; print(json.load(sys.stdin)["tag_name"])')
AV=$(curl -fsS -m 30 "https://dl-cdn.alpinelinux.org/alpine/v$(pin ALPINE_VERSION | cut -d. -f1,2)/releases/x86_64/latest-releases.yaml" |
    sed -n 's/^ *file: alpine-minirootfs-\(.*\)-x86_64.tar.gz$/\1/p' | head -1)
# Newest YARA-Forge rule package and its digest ("<tag> <sha256>").
YARA_LATEST=$(curl -fsS -m 30 https://api.github.com/repos/YARAHQ/yara-forge/releases/latest | python3 -I -c '
import json, sys
r = json.load(sys.stdin)
d = [a.get("digest") or "" for a in r["assets"] if a["name"] == "yara-forge-rules-core.zip"]
if d and d[0].startswith("sha256:"):
    print(r["tag_name"], d[0][7:])')
YV=${YARA_LATEST%% *}
STABLE=$(curl -fsS -m 30 https://alpinelinux.org/releases.json | python3 -I -c 'import json, sys; print(json.load(sys.stdin)["latest_stable"].lstrip("v"))' || true)
[ -n "$KV" ] && [ -n "$FCV" ] && [ -n "$AV" ] && [ -n "$YV" ] || die "could not read upstream versions"

PKGS=$(outdated_packages) || die "could not read Alpine's package index"
NPKG=$(printf '%s' "$PKGS" | grep -c . || true)
BUILT=$(sed -n 's/^built //p' "$INFO" 2>/dev/null || echo 0)
AGE=$(( ($(date +%s) - ${BUILT:-0}) / 86400 ))

if [ "$MODE" = status ]; then
    avail=0
    [ "$KV" = "$(pin KERNEL_VERSION)" ] && [ "$FCV" = "$(pin FC_VERSION)" ] && [ "$AV" = "$(pin ALPINE_VERSION)" ] && [ "$YV" = "$(pin YARA_RULES_VERSION)" ] && [ "$NPKG" = 0 ] || avail=1
    {
        echo "checked=$(date +%s)"
        echo "available=$avail"
        echo "kernel=$(pin KERNEL_VERSION) $KV"
        echo "firecracker=$(pin FC_VERSION) $FCV"
        echo "alpine=$(pin ALPINE_VERSION) $AV"
        echo "rules=$(pin YARA_RULES_VERSION) $YV"
        echo "image_age_days=$AGE"
        echo "packages=$NPKG"
        # The renderers first: they are what a document attacks.
        printf '%s\n' "$PKGS" | grep . | sort -k1,1 | awk '{k = ($1 ~ /^(mupdf|libreoffice|quickjs|python3|py3-oletools|musl)/) ? 0 : 1; print k, $0}' |
            sort -s -k1,1n | head -30 | cut -d' ' -f2- | sed 's/^/pkg=/'
    } | tee build/update-status.new
    mv -f build/update-status.new build/update-status
    exit 0
fi

changes=0
show() { # name current latest
    if [ "$2" = "$3" ]; then echo "   $1: $2 (newest)"; else echo "   $1: $2 -> $3"; changes=$((changes + 1)); fi
}
show "guest kernel (6.1 LTS)" "$(pin KERNEL_VERSION)" "$KV"
show "Firecracker" "$(pin FC_VERSION)" "$FCV"
show "Alpine base" "$(pin ALPINE_VERSION)" "$AV"
show "malware signatures (YARA-Forge)" "$(pin YARA_RULES_VERSION)" "$YV"
if [ "$NPKG" = 0 ]; then
    echo "   guest packages: all current"
else
    echo "   guest packages: $NPKG with newer versions"
    printf '%s\n' "$PKGS" | head -8 | awk '{print "      " $1 " " $2 " -> " $3}'
fi
case "$(pin ALPINE_VERSION)" in
    "$STABLE".*|"") ;;
    *) echo "   note: Alpine $STABLE is out; moving branch is a manual step (ALPINE_VERSION in scripts/bootstrap.sh)" ;;
esac
"$AIRLOCK" doctor 2>&1 | awk '/guest image (built|is)|image age/ {print; keep = /warn/; next} keep {print; keep = 0}' 
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
cp vendor/bin/vmlinux-airlock.stamp "$PREV/" 2>/dev/null || true
cp --reflink=auto --sparse=always "$ROOTFS" "$PREV/rootfs.ext4"
cp "$INFO" "$PREV/rootfs.info" 2>/dev/null || true

[ -z "${KSHA:-}" ] || { setpin KERNEL_VERSION "$KV"; setpin KERNEL_SHA256 "$KSHA"; }
[ -z "${FSHA:-}" ] || { setpin FC_VERSION "$FCV"; setpin FC_SHA256 "$FSHA"; setpin FC_CONFIG_SHA256 "$CSHA"; }
[ -z "${ASHA:-}" ] || { setpin ALPINE_VERSION "$AV"; setpin ALPINE_SHA256 "$ASHA"; }
[ "$YV" = "$(pin YARA_RULES_VERSION)" ] || { setpin YARA_RULES_VERSION "$YV"; setpin YARA_RULES_SHA256 "${YARA_LATEST#* }"; }

echo "==> Rebuilding and running the regression suite (log: $LOG)"
if [ "$KIT" = 1 ]; then
    # Test the new VM with the installed airlock (AIRLOCK_HOME: use the kit's build).
    build() { AIRLOCK="$AIRLOCK" AIRLOCK_HOME="$PWD" scripts/bootstrap.sh --vm-only --tests; }
else
    build() { scripts/bootstrap.sh --tests; }
fi
# The app's progress view reads the build as it happens (AIRLOCK_PROGRESS).
rc=0
if [ "${AIRLOCK_PROGRESS:-}" = 1 ]; then
    export AIRLOCK_PROGRESS
    rm -f build/.build-rc
    { build 2>&1 || echo $? > build/.build-rc; } | tee "$LOG"
    [ ! -f build/.build-rc ] || { rc=$(cat build/.build-rc); rm -f build/.build-rc; }
else
    build >"$LOG" 2>&1 || rc=$?
fi
if [ "$rc" != 0 ]; then
    restore
    tail -15 "$LOG" >&2
    die "the new version failed its checks; the previous version is back in place (full log: $LOG)"
fi

[ "$KIT" = 0 ] || deploy
echo "==> Updated"
if [ -f "$PREV/rootfs.info" ]; then
    # Renderers and the parts an exploit would go through.
    for p in mupdf-tools libreoffice-common quickjs python3 py3-oletools musl; do
        old=$(grep "^$p-[0-9]" "$PREV/rootfs.info" | head -1)
        new=$(grep "^$p-[0-9]" build/rootfs.info | head -1)
        [ "$old" = "$new" ] || echo "   $old -> $new"
    done
    old=$(grep '^rules ' "$PREV/rootfs.info" | cut -d' ' -f2); new=$(grep '^rules ' build/rootfs.info | cut -d' ' -f2)
    [ "$old" = "$new" ] || echo "   malware signatures: ${old:-none} -> $new"
    n=$(cat "$PREV/rootfs.info" build/rootfs.info | grep -v '^built\|^rules ' | sort | uniq -u | sed 's/-[0-9].*//' | sort -u | wc -l)
    echo "   $n guest package(s) changed in total"
fi
if [ "$KIT" = 1 ]; then
    tidy
    echo "   installed airlock updated"
else
    [ "$changes" = 0 ] || echo "   pins in scripts/bootstrap.sh changed — commit them"
    if installed; then
        scripts/install.sh >/dev/null 2>&1 && echo "   installed copy updated"
    fi
fi
echo "   undo: $0 --rollback"
