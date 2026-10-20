#!/bin/sh
# Builds dist/airlock-<version>-windows-x64-setup.exe on this Linux machine:
# the desktop app and the CLI cross-compiled for Windows (cargo-xwin), QEMU
# for Windows (pinned, checksum-verified), the same hardened kernel (as a
# bzImage) and the same VM image as on Linux, packed by NSIS (run with Wine).
# Unlike the AppImage, the VM image is inside: Windows cannot build it.
#
# Needs: the Windows Rust toolchain in build/win/toolchain (rustup target
# x86_64-pc-windows-msvc, cargo-xwin), tauri-cli, wine, 7z, llvm-objdump,
# mke2fs; build/rootfs.ext4 (guest/build-rootfs.sh) and
# vendor/bin/bzImage-airlock (guest/build-kernel.sh).
set -eu
cd "$(dirname "$0")/.."
ROOT=$PWD
W=$ROOT/build/win
T=$W/toolchain
export RUSTUP_HOME=$T/rustup CARGO_HOME=$T/cargo XWIN_CACHE_DIR=$T/xwin
PATH=$T/cargo/bin:$HOME/.cargo/bin:$PATH
TARGET=x86_64-pc-windows-msvc

# QEMU for Windows (Stefan Weil's builds, linked from qemu.org).
QEMU_SETUP=qemu-w64-setup-20260811.exe
QEMU_SHA512=$(cat "$ROOT/scripts/windows-qemu.sha512")
NSIS_ZIP_SHA256=c7d27f780ddb6cffb4730138cd1591e841f4b7edb155856901cdf5f214394fa1

mkdir -p "$W/dl"
if [ ! -f "$W/dl/$QEMU_SETUP" ]; then
    curl -fsSL -o "$W/dl/$QEMU_SETUP.part" "https://qemu.weilnetz.de/w64/$QEMU_SETUP"
    mv "$W/dl/$QEMU_SETUP.part" "$W/dl/$QEMU_SETUP"
fi
echo "$QEMU_SHA512  $W/dl/$QEMU_SETUP" | sha512sum -c --quiet
if [ ! -x "$W/nsis/nsis-3.11/makensis.exe" ] && [ ! -f "$W/nsis/nsis-3.11/makensis.exe" ]; then
    mkdir -p "$W/nsis"
    curl -fsSL -o "$W/nsis/nsis.zip" "https://downloads.sourceforge.net/project/nsis/NSIS%203/3.11/nsis-3.11.zip"
    echo "$NSIS_ZIP_SHA256  $W/nsis/nsis.zip" | sha256sum -c --quiet
    (cd "$W/nsis" && 7z x -y nsis.zip >/dev/null)
fi

# makensis for tauri: NSIS's own Windows program under Wine.
mkdir -p "$W/bin"
# tauri gives it Linux paths, on the command line and inside the scripts it
# writes; NSIS reads "/mnt/..." as an option. They become Wine's Z:/mnt/...
cat > "$W/bin/makensis" <<'EOF'
#!/bin/sh
export WINEDEBUG=-all WINEPREFIX="${AIRLOCK_WINEPREFIX:?}"
set -eu
n=$#
i=0
while [ $i -lt $n ]; do
    a=$1
    shift
    i=$((i+1))
    case $a in
        /*)
            if [ -e "$a" ]; then
                # The scripts next to it (installer.nsi and what it includes).
                for f in "$(dirname "$a")"/*.nsi "$(dirname "$a")"/*.nsh; do
                    [ -f "$f" ] && python3 -I -c 'import re, sys
p = sys.argv[1]
s = open(p, encoding="utf-8-sig").read()
s = re.sub(r"\"(/(?:mnt|home|tmp|run|usr|opt|var)/[^\"]*)\"", lambda m: "\"Z:" + m.group(1).replace("/", "\\") + "\"", s)
open(p, "w", encoding="utf-8").write(s)' "$f"
                done
                a="Z:$a"
            fi
            ;;
    esac
    set -- "$@" "$a"
done
exec wine "${AIRLOCK_MAKENSIS:?}" "$@"
EOF
export AIRLOCK_WINEPREFIX="$W/wineprefix" AIRLOCK_MAKENSIS="$W/nsis/nsis-3.11/makensis.exe"
chmod +x "$W/bin/makensis"
PATH=$W/bin:$PATH

# What goes next to the app: app/bundle-stage-win/vm/
STAGE=$ROOT/app/bundle-stage-win
rm -rf "$STAGE"
mkdir -p "$STAGE/vm/qemu/share"
rm -rf "$W/qemu-full"
mkdir -p "$W/qemu-full"
(cd "$W/qemu-full" && 7z x -y "$W/dl/$QEMU_SETUP" >/dev/null)
# Only qemu-system-x86_64 and the DLLs it loads (about 120 of 1200 MB).
(
    cd "$W/qemu-full"
    todo="qemu-system-x86_64.exe"
    seen=""
    while [ -n "$todo" ]; do
        set -- $todo
        f=$1
        shift
        todo="$*"
        for d in $(llvm-objdump -p "$f" 2>/dev/null | awk '/DLL Name:/{print $3}'); do
            [ -f "$d" ] || continue
            case " $seen " in *" $d "*) ;; *) seen="$seen $d"; todo="$todo $d" ;; esac
        done
    done
    cp qemu-system-x86_64.exe $seen COPYING COPYING.LIB "$STAGE/vm/qemu/"
    cp share/bios-microvm.bin share/linuxboot_dma.bin "$STAGE/vm/qemu/share/"
)
cp vendor/bin/bzImage-airlock "$STAGE/vm/bzImage"
cp build/rootfs.ext4 "$STAGE/vm/rootfs.ext4"
cp build/rootfs.info "$STAGE/vm/rootfs.info" 2>/dev/null || true
# The blank scratch disk the analysis VM writes to (Windows has no mke2fs).
mke2fs -q -t ext4 -O ^has_journal -E root_owner=0:0 -L scratch "$STAGE/vm/scratch.img" 96M
for f in known-malware.bin known-malware.info urlhaus.txt clamav.ext4 clamav.status; do
    [ -f "build/$f" ] && cp "build/$f" "$STAGE/vm/"
done
mkdir -p "$STAGE/vm/clamav"
[ -f build/clamav/daily.cvd ] && head -c 512 build/clamav/daily.cvd > "$STAGE/vm/clamav/daily.cvd"

(cd host && cargo xwin build --release -q --target $TARGET --bin airlock)
cp host/target/$TARGET/release/airlock.exe "$STAGE/vm/airlock.exe"

set -- --config tauri.nsis.json
[ -n "${AIRLOCK_EXTRA_CONFIG:-}" ] && set -- "$@" --config "$AIRLOCK_EXTRA_CONFIG"
rm -f app/target/$TARGET/release/bundle/nsis/*-setup.exe app/target/$TARGET/release/bundle/nsis/*-setup.exe.sig
if [ -z "${TAURI_SIGNING_PRIVATE_KEY:-}" ]; then
    printf '{"bundle":{"createUpdaterArtifacts":false}}' > app/target/no-updater-sig.json
    set -- "$@" --config target/no-updater-sig.json
fi
(cd app && cargo tauri build --runner cargo-xwin --target $TARGET --bundles nsis "$@")
mkdir -p dist
VERSION=$(sed -n 's/^  "version": "\(.*\)",/\1/p' app/tauri.conf.json)
VERSION=${AIRLOCK_VERSION:-$VERSION}
cp app/target/$TARGET/release/bundle/nsis/*-setup.exe "dist/airlock-$VERSION-windows-x64-setup.exe"
rm -f "dist/airlock-$VERSION-windows-x64-setup.exe.sig"
for s in app/target/$TARGET/release/bundle/nsis/*-setup.exe.sig; do [ -f "$s" ] && cp "$s" "dist/airlock-$VERSION-windows-x64-setup.exe.sig"; done
ls -lh "dist/airlock-$VERSION-windows-x64-setup.exe"
