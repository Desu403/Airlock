#!/bin/sh
# Builds the hardened guest kernel (rootless, inside the Alpine build root):
# Firecracker's microvm 6.1 config + guest/kernel-hardening.config.
# Inputs (checksum-verified downloads): vendor/dl/kernel/linux-$V.tar.xz,
# vendor/dl/kernel/microvm-6.1.config. Output: vendor/bin/vmlinux-airlock.
set -eu
cd "$(dirname "$0")/.."
. guest/lib.sh
V=${KERNEL_VERSION:-6.1.190}
SRC=build/kernel/linux-$V

if [ ! -d "$SRC" ]; then
    mkdir -p build/kernel
    tar xJf vendor/dl/kernel/linux-$V.tar.xz -C build/kernel
fi
ensure_buildroot build-base bc flex bison elfutils-dev openssl-dev perl linux-headers xz diffutils findutils python3

fakeroot_sh build/buildroot "
    cd /src/$SRC
    cp /src/vendor/dl/kernel/microvm-6.1.config .config
    # Merge the hardening fragment, then let Kconfig resolve dependencies.
    ./scripts/kconfig/merge_config.sh -m .config /src/guest/kernel-hardening.config >/dev/null
    make olddefconfig >/dev/null
    make -j\$(nproc) vmlinux >/src/build/kernel/build.log 2>&1 || { tail -40 /src/build/kernel/build.log; exit 1; }
"

# Every hardening line must have survived dependency resolution.
missing=0
while IFS= read -r line; do
    case "$line" in
        CONFIG_*=*) grep -qxF "$line" "$SRC/.config" || { echo "not applied: $line"; missing=$((missing+1)); } ;;
        "# CONFIG_"*" is not set")
            opt=${line#\# }; opt=${opt%% is not set}
            grep -q "^$opt=" "$SRC/.config" && { echo "still enabled: $opt"; missing=$((missing+1)); } ;;
    esac
done < guest/kernel-hardening.config
cp "$SRC/vmlinux" vendor/bin/vmlinux-airlock
echo "built vendor/bin/vmlinux-airlock ($(du -h vendor/bin/vmlinux-airlock | cut -f1)), $missing hardening option(s) not applied"
