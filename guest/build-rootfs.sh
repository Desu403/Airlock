#!/bin/sh
# Builds the guest image without root:
#  1. compiles airlock-agent (static musl) inside an Alpine build root via bwrap,
#  2. assembles a minimal Alpine guest root with only the renderer installed,
#  3. packs it (root-owned, via a fake-root tarball) into build/rootfs.ext4.
set -eu
cd "$(dirname "$0")/.."
. guest/lib.sh
RULES_ZIP=$(ls vendor/dl/yara-forge-rules-*.zip 2>/dev/null | sort -V | tail -1)
[ -n "$RULES_ZIP" ] || { echo "missing YARA rules in vendor/dl (run scripts/bootstrap.sh)" >&2; exit 1; }

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
    # Security fixes for the base system too, not only for what we add.
    apk upgrade --no-progress -q
    apk add --no-progress -q mupdf-tools quickjs \
        python3 py3-oletools yara \
        libreoffice-writer libreoffice-calc libreoffice-impress \
        font-liberation font-dejavu
    install -D -m 0644 -o 0 -g 0 /src/guest/office_triage.py /usr/lib/airlock/office_triage.py
    install -D -m 0644 -o 0 -g 0 /src/guest/pdf_walk.js /usr/lib/airlock/pdf_walk.js
    install -D -m 0644 -o 0 -g 0 /src/guest/unpack.py /usr/lib/airlock/unpack.py
    # Known-malware signatures (YARA-Forge rule package), compiled once here.
    mkdir /tmp/rules && unzip -q /src/'"$RULES_ZIP"' -d /tmp/rules
    set -- /tmp/rules/packages/*/*.yar
    python3 -I /src/guest/yara_meta.py "$@" > /usr/lib/airlock/yara-meta.tsv
    yarac -w "$@" /usr/lib/airlock/rules.yarc
    chmod 0644 /usr/lib/airlock/yara-meta.tsv /usr/lib/airlock/rules.yarc
    echo "rules $(basename '"$RULES_ZIP"' .zip) $(grep -c . /usr/lib/airlock/yara-meta.tsv)" > /src/'"$B"'/rootfs.rules.tmp
    rm -rf /tmp/rules
    # Prebuilt font cache + LibreOffice profile: no first-run writes inside the
    # VM, and the autopsy can diff the per-run profile against this template.
    fc-cache -f >/dev/null 2>&1 || true
    HOME=/tmp SAL_USE_VCLPLUGIN=svp /usr/lib/libreoffice/program/soffice.bin \
        -env:UserInstallation=file:///usr/lib/airlock/lo-profile-template \
        --headless --invisible --nologo --norestore --terminate_after_init >/dev/null 2>&1 || true
    test -d /usr/lib/airlock/lo-profile-template/user
    apk info -v 2>/dev/null | sort > /src/'"$B"'/rootfs.packages.tmp
    rm -rf /sbin/apk /etc/apk /lib/apk /var/cache/apk /usr/share/apk
    install -m 0755 -o 0 -g 0 /src/'"$AGENT"' /sbin/airlock-agent
    # Only ever reachable resolver: the host sinkhole (analysis mode).
    echo "nameserver 10.0.0.1" > /etc/resolv.conf
'
rmdir $B/guestroot/src
# What went into this image, and when (read by doctor and scripts/update.sh).
{ echo "built $(date +%s)"; cat $B/rootfs.rules.tmp $B/rootfs.packages.tmp; } > $B/rootfs.info.new
rm -f $B/rootfs.packages.tmp $B/rootfs.rules.tmp
# Pack from inside the fake root so every file is recorded as root:root.
fakeroot_sh $B/buildroot 'tar -C /src/'"$B"'/guestroot --numeric-owner --owner=0 --group=0 -cf /src/'"$B"'/guestroot.tar .'

# 3. Filesystem image (ownership taken from the fake-root tarball = root:root).
rm -f $B/rootfs.ext4
SIZE_MB=$(( $(stat -c %s $B/guestroot.tar) / 1048576 * 12 / 10 + 64 ))
mke2fs -q -t ext4 -L airlock-guest -O ^has_journal -d $B/guestroot.tar $B/rootfs.ext4 ${SIZE_MB}M
mv -f $B/rootfs.info.new $B/rootfs.info
echo "built $B/rootfs.ext4 ($(du -h $B/rootfs.ext4 | cut -f1) on disk)"
