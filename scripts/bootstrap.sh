#!/bin/sh
# One-shot setup: fetch pinned, checksum-verified inputs and build everything.
# No root needed. Usage: scripts/bootstrap.sh [--no-app] [--tests] [--vm-only]
# --vm-only (automatic in an installed update kit, which has no host/ or
# app/): build only the VM (kernel, image, Firecracker); no Rust on the host.
#
# Pinned inputs (version + SHA-256). Bump both together.
FC_VERSION=v1.17.0
FC_SHA256=06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558
ALPINE_VERSION=3.24.2
ALPINE_SHA256=c5ca053cfe1d85c5b96dff8b9bc57045f7f184a30ffb6b65776409ca90388677
KERNEL_VERSION=6.1.190
KERNEL_SHA256=8aa50daca0412a3d0a61a87af3744f39773d40b3132635fb7bc9be652cdb7b0c
# Firecracker's microvm guest config, from the same Firecracker release tag.
FC_CONFIG_SHA256=153ca1b40f3312bfb40b7587b471ea548a915f98f480f0d0892a1537957a2147
# Known-malware signatures: YARA-Forge's quality-tested "core" rule package.
YARA_RULES_VERSION=20261018
YARA_RULES_SHA256=d5b5f0006a0c58684459c3967b6aaae94f1e128597ed23ea5d4e8f16965a74ba

set -eu
cd "$(dirname "$0")/.."
APP=1
TESTS=0
VM_ONLY=0
[ -d host ] || VM_ONLY=1
for a in "$@"; do
    case "$a" in
        --no-app) APP=0 ;;
        --tests) TESTS=1 ;;
        --vm-only) VM_ONLY=1 ;;
        *) echo "usage: $0 [--no-app] [--tests] [--vm-only]" >&2; exit 2 ;;
    esac
done
[ "$VM_ONLY" = 0 ] || APP=0
# The airlock binary that tests and checks the result.
AIRLOCK=${AIRLOCK:-host/target/release/airlock}

step() { printf '\n==> %s\n' "$*"; }
die() { echo "error: $*" >&2; exit 1; }

# fetch URL DEST SHA256: download unless DEST already has the right hash.
fetch() {
    if [ -f "$2" ] && echo "$3  $2" | sha256sum -c --quiet 2>/dev/null; then
        echo "   have $(basename "$2")"
        return
    fi
    echo "   fetching $(basename "$2")"
    curl -fL --progress-bar -o "$2.part" "$1"
    echo "$3  $2.part" | sha256sum -c --quiet || { rm -f "$2.part"; die "checksum mismatch for $1"; }
    mv "$2.part" "$2"
}

step "Checking host prerequisites"
[ "$(uname -m)" = x86_64 ] || die "only x86_64 is supported for now"
missing=""
NEED="curl sha256sum tar xz bwrap mke2fs ip nft setpriv python3 file"
[ "$VM_ONLY" = 1 ] || NEED="$NEED cargo"
for c in $NEED; do
    command -v "$c" >/dev/null 2>&1 || missing="$missing $c"
done
[ -z "$missing" ] || die "missing commands:$missing (see README: Requirements)"
[ -r /dev/kvm ] && [ -w /dev/kvm ] || die "no read/write access to /dev/kvm (enable virtualisation in BIOS; add yourself to the 'kvm' group)"
bwrap --unshare-user --uid 0 --ro-bind / / true 2>/dev/null || die "unprivileged user namespaces are blocked (see README: Troubleshooting)"
mke2fs -V 2>&1 | awk 'NR==1 { split($2, v, "."); exit !(v[1] > 1 || (v[1] == 1 && v[2] >= 47)) }' \
    || die "mke2fs >= 1.47 required (for building images from tarballs)"

step "Fetching pinned inputs"
mkdir -p vendor/dl/kernel vendor/bin
fetch "https://github.com/firecracker-microvm/firecracker/releases/download/$FC_VERSION/firecracker-$FC_VERSION-x86_64.tgz" \
    "vendor/dl/firecracker-$FC_VERSION-x86_64.tgz" "$FC_SHA256"
fetch "https://dl-cdn.alpinelinux.org/alpine/v${ALPINE_VERSION%.*}/releases/x86_64/alpine-minirootfs-$ALPINE_VERSION-x86_64.tar.gz" \
    "vendor/dl/alpine-minirootfs-$ALPINE_VERSION-x86_64.tar.gz" "$ALPINE_SHA256"
rm -f $(ls vendor/dl/yara-forge-rules-core-*.zip 2>/dev/null | grep -v "core-$YARA_RULES_VERSION.zip") 2>/dev/null || true
fetch "https://github.com/YARAHQ/yara-forge/releases/download/$YARA_RULES_VERSION/yara-forge-rules-core.zip" \
    "vendor/dl/yara-forge-rules-core-$YARA_RULES_VERSION.zip" "$YARA_RULES_SHA256"
# The kernel is only rebuilt when its inputs change (version, base config,
# hardening fragment).
KSTAMP="$KERNEL_VERSION $FC_CONFIG_SHA256 $(sha256sum guest/kernel-hardening.config | cut -c1-64)"
NEED_KERNEL=1
[ -f vendor/bin/vmlinux-airlock ] && [ "$(cat vendor/bin/vmlinux-airlock.stamp 2>/dev/null)" = "$KSTAMP" ] && NEED_KERNEL=0
if [ "$NEED_KERNEL" = 1 ]; then
    fetch "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$KERNEL_VERSION.tar.xz" \
        "vendor/dl/kernel/linux-$KERNEL_VERSION.tar.xz" "$KERNEL_SHA256"
    fetch "https://raw.githubusercontent.com/firecracker-microvm/firecracker/$FC_VERSION/resources/guest_configs/microvm-kernel-ci-x86_64-6.1.config" \
        "vendor/dl/kernel/microvm-6.1.config" "$FC_CONFIG_SHA256"
fi

tar xzf "vendor/dl/firecracker-$FC_VERSION-x86_64.tgz" -C vendor/dl
install -m 0755 "vendor/dl/release-$FC_VERSION-x86_64/firecracker-$FC_VERSION-x86_64" vendor/bin/firecracker

if [ "$NEED_KERNEL" = 1 ]; then
    step "Building the hardened guest kernel (a few minutes)"
    KERNEL_VERSION=$KERNEL_VERSION guest/build-kernel.sh
    echo "$KSTAMP" > vendor/bin/vmlinux-airlock.stamp
else
    step "Guest kernel $KERNEL_VERSION is already built"
fi

step "Building the guest image (downloads Alpine packages incl. LibreOffice)"
guest/build-rootfs.sh

if [ "$VM_ONLY" = 0 ]; then
    step "Building the airlock CLI"
    (cd host && cargo build --release)
fi

if [ "$APP" = 1 ]; then
    step "Building the desktop app"
    (cd app && cargo build --release)
fi

if [ "$TESTS" = 1 ]; then
    step "Fetching test fixtures and running the regression suite"
    tests/fetch-fixtures.sh
    AIRLOCK=$AIRLOCK tests/run.sh
fi

step "Done"
[ "$VM_ONLY" = 1 ] && exit 0
"$AIRLOCK" doctor
echo
echo "CLI:  host/target/release/airlock view|analyze <file>"
[ "$APP" = 1 ] && echo "App:  app/target/release/airlock-app [file]"
echo "Install for your user (launcher, 'Open with airlock'): scripts/install.sh"
exit 0
