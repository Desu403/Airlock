# Verification of the VM's upstream inputs, shared by scripts/update.sh and
# tests/update-verify.sh (sourced, not run). Every check runs on every daily
# check, not only when a version changes, so a broken check shows up the day
# it breaks instead of in the middle of a security update.
#
# Failures are put in two kinds, so the app can tell them apart:
#   VERIFY_KIND=unchecked  could not check (network, a key or file missing,
#                          upstream changed its format or signing key)
#   VERIFY_KIND=changed    checked, and it does not match: a download or a
#                          signed list was altered — never installed
# VERIFY_ERR holds one plain-language sentence.

# kernel.org signs sha256sums.asc with its checksum autosigner, a key kept on
# an off-network system (https://www.kernel.org/signature.html). The key
# ships with airlock (scripts/keys/); only this fingerprint is accepted.
KORG_AUTOSIGNER=B8868C80BA62A1FFFAF5FDA9632D3A06589DA6B1
KORG_KEY=${KORG_KEY:-scripts/keys/kernel.org-autosigner.asc}
KORG_SUMS_URL=${KORG_SUMS_URL:-https://cdn.kernel.org/pub/linux/kernel/v6.x/sha256sums.asc}

VERIFY_ERR=
VERIFY_KIND=
vfail() { VERIFY_KIND=$1; VERIFY_ERR=$2; return 1; }

# verify_clearsigned FILE KEYFILE FINGERPRINT OUT
# Checks FILE's clear-signature against exactly the key FINGERPRINT (taken
# from KEYFILE, never from a keyserver) and writes only the signed text to
# OUT: lines outside the signature are never read.
verify_clearsigned() {
    [ -s "$2" ] || { vfail unchecked "the trusted key file $2 is missing"; return 1; }
    command -v gpg >/dev/null || { vfail unchecked "gpg is needed to check signatures"; return 1; }
    _g=$(mktemp -d) && chmod 700 "$_g"
    if ! GNUPGHOME=$_g gpg -q --batch --import "$2" >/dev/null 2>&1; then
        rm -rf "$_g"; vfail unchecked "the trusted key in $2 could not be loaded"; return 1
    fi
    rm -f "$4"
    _st=$(GNUPGHOME=$_g gpg --batch --status-fd 1 --output "$4" --decrypt "$1" 2>/dev/null || true)
    rm -rf "$_g"
    # VALIDSIG <signing key fpr> ... <primary key fpr>: either may be ours.
    if printf '%s\n' "$_st" | awk -v f="$3" '$1 == "[GNUPG:]" && $2 == "VALIDSIG" && ($3 == f || $NF == f) {ok = 1} END {exit !ok}' &&
       ! printf '%s\n' "$_st" | grep -q '^\[GNUPG:\] BADSIG'; then
        [ -s "$4" ] && return 0
    fi
    rm -f "$4"
    if printf '%s\n' "$_st" | grep -q '^\[GNUPG:\] BADSIG'; then
        vfail changed "the file was changed after it was signed"
    elif printf '%s\n' "$_st" | grep -q '^\[GNUPG:\] \(ERRSIG\|NO_PUBKEY\)'; then
        vfail unchecked "it is signed with a different key than the one airlock trusts (the publisher may have changed its key)"
    elif printf '%s\n' "$_st" | grep -q '^\[GNUPG:\] \(GOODSIG\|VALIDSIG\)'; then
        vfail unchecked "it is signed with a different key than the one airlock trusts (the publisher may have changed its key)"
    else
        vfail changed "it carries no valid signature"
    fi
}

# sha_from_list FILE NAME: the checksum for NAME in a "sha  name" list.
sha_from_list() { awk -v f="$2" '$2 == f && length($1) == 64 {print $1; exit}' "$1"; }

# verify_kernel VERSION [PINNED_SHA] -> KSHA. With PINNED_SHA (the version
# airlock already uses) it must match kernel.org's signed checksum.
verify_kernel() {
    _d=$(mktemp -d)
    if ! curl -fsS -m 60 -o "$_d/sums.asc" "$KORG_SUMS_URL"; then
        rm -rf "$_d"; vfail unchecked "kernel.org's checksum list could not be downloaded"; return 1
    fi
    if ! verify_clearsigned "$_d/sums.asc" "$KORG_KEY" "$KORG_AUTOSIGNER" "$_d/sums"; then
        rm -rf "$_d"; VERIFY_ERR="kernel.org checksum list: $VERIFY_ERR"; return 1
    fi
    KSHA=$(sha_from_list "$_d/sums" "linux-$1.tar.xz")
    rm -rf "$_d"
    [ -n "$KSHA" ] || { vfail unchecked "kernel.org's signed list has no checksum for linux-$1.tar.xz"; return 1; }
    if [ -n "${2:-}" ] && [ "$2" != "$KSHA" ]; then
        vfail changed "the kernel airlock uses (linux-$1) does not match kernel.org's signed checksum"; return 1
    fi
}

# verify_firecracker VERSION [PINNED_SHA] -> FSHA, CSHA
verify_firecracker() {
    FSHA=$(curl -fsSL -m 60 "https://github.com/firecracker-microvm/firecracker/releases/download/$1/firecracker-$1-x86_64.tgz.sha256.txt" | awk '{print $1; exit}' || true)
    [ ${#FSHA} = 64 ] || { vfail unchecked "no checksum published for Firecracker $1 (or GitHub could not be reached)"; return 1; }
    CSHA=$(curl -fsSL -m 60 "https://raw.githubusercontent.com/firecracker-microvm/firecracker/$1/resources/guest_configs/microvm-kernel-ci-x86_64-6.1.config" | sha256sum | awk '{print $1}')
    if [ -n "${2:-}" ] && [ "$2" != "$FSHA" ]; then
        vfail changed "the Firecracker airlock uses ($1) does not match its published checksum"; return 1
    fi
}

# verify_alpine VERSION [PINNED_SHA] -> ASHA
verify_alpine() {
    ASHA=$(curl -fsS -m 30 "https://dl-cdn.alpinelinux.org/alpine/v$(echo "$1" | cut -d. -f1,2)/releases/x86_64/latest-releases.yaml" |
        awk -v f="alpine-minirootfs-$1-x86_64.tar.gz" '$1 == "file:" {hit = ($2 == f)} hit && $1 == "sha256:" {print $2; exit}' || true)
    [ ${#ASHA} = 64 ] || { vfail unchecked "no checksum published for Alpine $1 (or Alpine's server could not be reached)"; return 1; }
    if [ -n "${2:-}" ] && [ "$2" != "$ASHA" ]; then
        vfail changed "the Alpine base airlock uses ($1) does not match its published checksum"; return 1
    fi
}

# verify_rules PINNED_VERSION PINNED_SHA LATEST_VERSION LATEST_SHA
verify_rules() {
    [ ${#4} = 64 ] || { vfail unchecked "YARA-Forge published no checksum for its rules $3"; return 1; }
    if [ "$1" = "$3" ] && [ "$2" != "$4" ]; then
        vfail changed "the malware signatures airlock uses ($1) do not match their published checksum"; return 1
    fi
}
