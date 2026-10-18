#!/bin/sh
# First-time setup for this computer: what airlock needs from the system, in
# plain words, and how to get it. Used by the AppImage's setup screen (it
# reads the "@@" lines) and runnable by hand.
#
#   scripts/setup.sh check   list each requirement: ok / fail / warn
#   scripts/setup.sh plan    print the root script that would fix what fails
#   scripts/setup.sh fix     run that script with one password prompt
#                            (pkexec, or sudo in a terminal)
#   scripts/setup.sh build   build the VM (kernel, image) in user space and
#                            install it to ~/.local/lib/airlock; no root
#
# Nothing here weakens the system beyond what airlock's design needs:
# /dev/kvm and /dev/net/tun usable by any user (systemd's default on many
# distributions), a spare range of user ids for the VM jail, and on Ubuntu
# unprivileged user namespaces (which bubblewrap-based sandboxes rely on).
set -eu
cd "$(dirname "$0")/.."
MODE=${1:-check}
USER_NAME=$(id -un)
LIB=${AIRLOCK_LIB:-$HOME/.local/lib/airlock}

say() { printf '@@%s\t%s\t%s\n' "$1" "$2" "$3"; }   # @@status <tab> id <tab> text
have() { command -v "$1" >/dev/null 2>&1; }

# --- package manager and package names -------------------------------------
PM=none
if have apt-get; then PM=apt; elif have dnf; then PM=dnf; elif have pacman; then PM=pacman; elif have zypper; then PM=zypper; fi
pkg_for() {
    case "$PM:$1" in
        *:bwrap) echo bubblewrap ;;
        *:xdg-dbus-proxy) echo xdg-dbus-proxy ;;
        *:mke2fs) echo e2fsprogs ;;
        dnf:ip) echo iproute ;;
        *:ip) echo iproute2 ;;
        *:nft) echo nftables ;;
        *:setpriv | *:prlimit | *:unshare) echo util-linux ;;
        apt:newuidmap) echo uidmap ;;
        dnf:newuidmap) echo shadow-utils ;;
        *:newuidmap) echo shadow ;;
        apt:xz | zypper:xz) echo xz-utils ;;
        *:xz) echo xz ;;
        pacman:python3) echo python ;;
        *:sha256sum) echo coreutils ;;
        *) echo "$1" ;;
    esac
}
install_cmd() {
    case $PM in
        apt) echo "apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -y -q $*" ;;
        dnf) echo "dnf install -y -q $*" ;;
        pacman) echo "pacman -S --needed --noconfirm $*" ;;
        zypper) echo "zypper --non-interactive install $*" ;;
        *) echo "echo 'install these packages with your package manager: $*' >&2; false" ;;
    esac
}

# --- checks --------------------------------------------------------------------
# Each check appends to PLAN (root fixes) and MISSING (packages).
PLAN=""
MISSING=""
FAILED=0
add_plan() { PLAN="$PLAN$1
"; }

check_all() {
    if [ "$(uname -m)" = x86_64 ]; then say ok arch "64-bit Intel/AMD processor"; else say fail arch "airlock needs a 64-bit Intel/AMD (x86_64) computer for now"; FAILED=1; fi

    if [ ! -e /dev/kvm ]; then
        say fail kvm "Hardware virtualisation is off or unsupported: turn on \"Intel VT-x\" or \"AMD-V / SVM\" in the computer's BIOS/UEFI settings, then restart"
        FAILED=1
    elif [ "$(stat -c %a /dev/kvm)" != 666 ]; then
        say fix kvm "The virtualisation device (/dev/kvm) must be usable by airlock's separate VM user"
        add_plan "printf 'KERNEL==\"kvm\", MODE=\"0666\"\nKERNEL==\"tun\", MODE=\"0666\"\n' > /etc/udev/rules.d/65-airlock.rules
chmod 0666 /dev/kvm"
    else
        say ok kvm "Hardware virtualisation (KVM) is available"
    fi

    if [ ! -e /dev/net/tun ]; then
        say fix tun "The virtual network device (for the fake internet used in analysis) is not loaded"
        add_plan "modprobe tun
echo tun > /etc/modules-load.d/airlock.conf"
    fi
    if [ ! -e /dev/net/tun ] || [ "$(stat -c %a /dev/net/tun)" != 666 ]; then
        [ -e /dev/net/tun ] && say fix tun-mode "The virtual network device must be usable by airlock's separate VM user"
        add_plan "[ -f /etc/udev/rules.d/65-airlock.rules ] || printf 'KERNEL==\"kvm\", MODE=\"0666\"\nKERNEL==\"tun\", MODE=\"0666\"\n' > /etc/udev/rules.d/65-airlock.rules
chmod 0666 /dev/net/tun 2>/dev/null || true"
    else
        say ok tun "Virtual network device is available"
    fi

    for c in curl sha256sum tar xz bwrap mke2fs ip nft setpriv prlimit unshare newuidmap python3 file xdg-dbus-proxy; do
        if ! have "$c"; then MISSING="$MISSING $(pkg_for "$c")"; fi
    done
    MISSING=$(echo "$MISSING" | tr ' ' '\n' | grep . | sort -u | tr '\n' ' ')
    if [ -n "$MISSING" ]; then
        say fix packages "Some standard system tools are missing: $MISSING"
        add_plan "$(install_cmd $MISSING)"
    else
        say ok packages "All needed system tools are installed"
    fi

    if have mke2fs && ! mke2fs -V 2>&1 | awk 'NR==1 { split($2, v, "."); exit !(v[1] > 1 || (v[1] == 1 && v[2] >= 47)) }'; then
        say fail e2fsprogs "Your system's e2fsprogs is older than 1.47; airlock needs a newer Linux distribution release"
        FAILED=1
    fi

    if grep -qs "^$USER_NAME:" /etc/subuid && grep -qs "^$USER_NAME:" /etc/subgid; then
        say ok subuid "A spare range of user ids is reserved for the VM jail"
    else
        # The first free 65536-id block above every existing range.
        start=$(cat /etc/subuid /etc/subgid 2>/dev/null | awk -F: '{ e = $2 + $3; if (e > m) m = e } END { s = (m > 100000 ? m : 100000); print s }')
        say fix subuid "VMs run as a separate spare user (never as you): a range of user ids must be reserved for it"
        add_plan "usermod --add-subuids $start-$((start + 65535)) --add-subgids $start-$((start + 65535)) $USER_NAME"
    fi

    # Ubuntu 23.10+ blocks unprivileged user namespaces through AppArmor;
    # older Debian kernels have their own switch.
    if [ "$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null)" = 1 ]; then
        say fix userns "Ubuntu blocks the sandbox feature airlock is built on (unprivileged user namespaces); it will be allowed"
        add_plan "echo 'kernel.apparmor_restrict_unprivileged_userns = 0' > /etc/sysctl.d/60-airlock-userns.conf
sysctl -q -w kernel.apparmor_restrict_unprivileged_userns=0"
    elif [ "$(cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null)" = 0 ]; then
        say fix userns "The sandbox feature airlock is built on (unprivileged user namespaces) is turned off; it will be turned on"
        add_plan "echo 'kernel.unprivileged_userns_clone = 1' > /etc/sysctl.d/60-airlock-userns.conf
sysctl -q -w kernel.unprivileged_userns_clone=1"
    elif have bwrap && ! bwrap --unshare-user --uid 0 --ro-bind / / true 2>/dev/null; then
        say fail userns "The sandbox feature airlock is built on (unprivileged user namespaces) is blocked by this system's policy"
        FAILED=1
    else
        say ok userns "Sandboxing (user namespaces) is allowed"
    fi

    if [ -f "$LIB/rootfs.ext4" ] && [ -f "$LIB/vmlinux" ] && [ -f "$LIB/firecracker" ] && [ -f "$LIB/sinkhole" ]; then
        say ok vm "The secure viewer (VM image) is built"
    else
        say build vm "The secure viewer (VM image) still has to be built: downloads about 600 MB and takes 10-20 minutes"
    fi
}

case $MODE in
    check)
        check_all
        [ "$FAILED" = 0 ] || exit 1
        ;;
    plan)
        check_all >/dev/null
        [ -n "$PLAN" ] && printf 'set -e\n%s' "$PLAN"
        ;;
    fix)
        check_all >/dev/null
        [ -n "$PLAN" ] || { echo "nothing to fix"; exit 0; }
        script=$(mktemp)
        printf 'set -e\n%s' "$PLAN" > "$script"
        chmod 0644 "$script"
        echo "airlock needs administrator rights once, to run:"
        sed 's/^/    /' "$script"
        if have pkexec && [ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]; then
            pkexec /bin/sh "$script"
        elif have sudo; then
            sudo /bin/sh "$script"
        else
            echo "run it as root: sh $script" >&2
            exit 1
        fi
        rm -f "$script"
        # New ranges and udev modes apply at once; group changes are not used.
        echo "done"
        ;;
    build)
        # Same recipe as scripts/install.sh, VM part only: everything happens
        # in user space from pinned, checksum-verified downloads.
        KIT=$LIB/kit
        mkdir -p "$KIT"
        if [ "$(cd "$KIT" && pwd)" != "$(pwd)" ]; then
            for d in guest guest-agent proto scripts tests; do
                rm -rf "${KIT:?}/$d"
                cp -r "$d" "$KIT/$d"
            done
            touch "$KIT/.airlock-kit"
        fi
        (cd "$KIT" && scripts/bootstrap.sh --vm-only)
        printf '\n==> Installing the secure viewer\n'
        mkdir -p "$LIB"
        install -m 0755 "$KIT/vendor/bin/firecracker" "$LIB/firecracker.new" && mv -f "$LIB/firecracker.new" "$LIB/firecracker"
        install -m 0644 "$KIT/vendor/bin/vmlinux-airlock" "$LIB/vmlinux.new" && mv -f "$LIB/vmlinux.new" "$LIB/vmlinux"
        cp --sparse=always "$KIT/build/rootfs.ext4" "$LIB/rootfs.ext4.new" && chmod 0644 "$LIB/rootfs.ext4.new" && mv -f "$LIB/rootfs.ext4.new" "$LIB/rootfs.ext4"
        [ -f "$KIT/build/rootfs.info" ] && install -m 0644 "$KIT/build/rootfs.info" "$LIB/rootfs.info"
        # The fake-internet helper ships prebuilt (in the AppImage) or from host/.
        SINKHOLE=${AIRLOCK_SINKHOLE:-host/target/release/sinkhole}
        [ -f "$SINKHOLE" ] && install -m 0755 "$SINKHOLE" "$LIB/sinkhole.new" && mv -f "$LIB/sinkhole.new" "$LIB/sinkhole"
        echo "@@ok	vm	The secure viewer is built and installed"
        ;;
    *)
        echo "usage: $0 check|plan|fix|build" >&2
        exit 2
        ;;
esac
