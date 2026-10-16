#!/bin/sh
# Builds the guest image without root:
#  1. compiles airlock-agent (static musl) inside an Alpine build root via bwrap,
#  2. assembles a minimal Alpine guest root with only the renderer installed,
#  3. packs it (root-owned, via a fake-root tarball) into build/rootfs.ext4.
set -eu
cd "$(dirname "$0")/.."
. guest/lib.sh

# 1. Build root with the Rust toolchain.
ensure_buildroot cargo tar file
fakeroot_sh $B/buildroot '
    cd /src/guest-agent
    RUSTFLAGS="-C target-feature=+crt-static" CARGO_HOME=/src/build/cargo-home \
        cargo build --release -q --target-dir /src/build/agent-target
'
AGENT=$B/agent-target/release/airlock-agent
file "$AGENT" | grep -q "static" || { echo "agent is not static" >&2; exit 1; }

# 2. Guest root: renderers (MuPDF, QuickJS, LibreOffice) + oletools; no package manager left behind.
rm -rf $B/guestroot && mkdir -p $B/guestroot
tar xzf "$ALPINE_TAR" -C $B/guestroot
fakeroot_sh $B/guestroot '
    apk add --no-progress -q mupdf-tools quickjs \
        python3 py3-oletools \
        libreoffice-writer libreoffice-calc libreoffice-impress \
        font-liberation font-dejavu
    install -D -m 0644 -o 0 -g 0 /src/guest/office_triage.py /usr/lib/airlock/office_triage.py
    install -D -m 0644 -o 0 -g 0 /src/guest/pdf_scripts.js /usr/lib/airlock/pdf_scripts.js
    # Prebuilt font cache + LibreOffice profile: no first-run writes inside the
    # VM, and the autopsy can diff the per-run profile against this template.
    fc-cache -f >/dev/null 2>&1 || true
    HOME=/tmp SAL_USE_VCLPLUGIN=svp /usr/lib/libreoffice/program/soffice.bin \
        -env:UserInstallation=file:///usr/lib/airlock/lo-profile-template \
        --headless --invisible --nologo --norestore --terminate_after_init >/dev/null 2>&1 || true
    test -d /usr/lib/airlock/lo-profile-template/user
    rm -rf /sbin/apk /etc/apk /lib/apk /var/cache/apk /usr/share/apk
    install -m 0755 -o 0 -g 0 /src/'"$AGENT"' /sbin/airlock-agent
    # Only ever reachable resolver: the host sinkhole (analysis mode).
    echo "nameserver 10.0.0.1" > /etc/resolv.conf
'
rmdir $B/guestroot/src
# Pack from inside the fake root so every file is recorded as root:root.
fakeroot_sh $B/buildroot 'tar -C /src/'"$B"'/guestroot --numeric-owner --owner=0 --group=0 -cf /src/'"$B"'/guestroot.tar .'

# 3. Filesystem image (ownership taken from the fake-root tarball = root:root).
rm -f $B/rootfs.ext4
SIZE_MB=$(( $(stat -c %s $B/guestroot.tar) / 1048576 * 12 / 10 + 64 ))
mke2fs -q -t ext4 -L airlock-guest -O ^has_journal -d $B/guestroot.tar $B/rootfs.ext4 ${SIZE_MB}M
echo "built $B/rootfs.ext4 ($(du -h $B/rootfs.ext4 | cut -f1) on disk)"
