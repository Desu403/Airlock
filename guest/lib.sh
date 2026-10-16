# Shared helpers for the rootless guest build scripts (sourced, not run).
# Expects to be sourced from the repository root.

ROOT=$PWD
B=build
ALPINE_TAR=$(ls vendor/dl/alpine-minirootfs-*-x86_64.tar.gz 2>/dev/null | sort -V | tail -1)
[ -n "$ALPINE_TAR" ] || { echo "missing Alpine minirootfs in vendor/dl (run scripts/bootstrap.sh)" >&2; exit 1; }

# fakeroot_sh DIR SCRIPT: run SCRIPT as fake root inside the Alpine tree DIR,
# with network, and the repository mounted at /src.
fakeroot_sh() {
    dir=$1; shift
    cp /etc/resolv.conf "$dir/etc/resolv.conf"
    bwrap --unshare-user --uid 0 --gid 0 --bind "$dir" / --dev /dev --proc /proc --tmpfs /tmp \
        --share-net --bind "$ROOT" /src \
        --clearenv --setenv PATH /usr/sbin:/usr/bin:/sbin:/bin --setenv HOME /root \
        -- /bin/sh -euc "$*"
}

# The Alpine build root (compilers etc.) is shared by all build scripts.
ensure_buildroot() {
    if [ ! -x $B/buildroot/sbin/apk ]; then
        rm -rf $B/buildroot && mkdir -p $B/buildroot
        tar xzf "$ALPINE_TAR" -C $B/buildroot
    fi
    fakeroot_sh $B/buildroot "apk add --no-progress -q $*"
}
