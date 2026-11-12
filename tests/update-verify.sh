#!/bin/sh
# The update path's download checks (scripts/verify.sh), offline: a signed
# checksum list must be accepted only when signed by exactly the trusted key,
# and anything else refused with the right kind of message. Uses throwaway
# keys made here; the live servers are covered by `scripts/update.sh --verify`
# (the daily canary).
set -u
cd "$(dirname "$0")/.."
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
fails=0
pass() { echo "ok   $1"; }
fail() { echo "FAIL $1"; fails=$((fails + 1)); }
. scripts/verify.sh

# The shipped kernel.org key really is the pinned fingerprint.
fpr=$(gpg --with-colons --show-keys scripts/keys/kernel.org-autosigner.asc 2>/dev/null | awk -F: '$1 == "fpr" {print $10; exit}')
[ "$fpr" = "$KORG_AUTOSIGNER" ] && pass "shipped kernel.org key matches the pinned fingerprint" || fail "shipped kernel.org key is $fpr, expected $KORG_AUTOSIGNER"

# Two throwaway signing keys: "trusted" and "other".
mkkey() {
    mkdir -m 700 "$T/$1"
    GNUPGHOME=$T/$1 gpg -q --batch --pinentry-mode loopback --passphrase '' --quick-gen-key "$1 <$1@airlock.test>" ed25519 sign never 2>/dev/null
    GNUPGHOME=$T/$1 gpg --batch --armor --export > "$T/$1.asc" 2>/dev/null
    GNUPGHOME=$T/$1 gpg --with-colons --list-keys 2>/dev/null | awk -F: '$1 == "fpr" {print $10; exit}'
}
TRUSTED=$(mkkey trusted)
OTHER=$(mkkey other)
[ ${#TRUSTED} = 40 ] && [ ${#OTHER} = 40 ] || { echo "FAIL could not make test keys"; exit 1; }

GOOD=1111111111111111111111111111111111111111111111111111111111111111
EVIL=2222222222222222222222222222222222222222222222222222222222222222
printf '%s  linux-6.1.500.tar.xz\n%s  linux-6.1.501.tar.xz\n' "$GOOD" "$GOOD" > "$T/sums"
sign() { GNUPGHOME=$T/$1 gpg -q --batch --pinentry-mode loopback --passphrase '' --clearsign -o "$2" "$T/sums"; }
sign trusted "$T/list-good.asc"
sign other "$T/list-other.asc"
sed "s/^$GOOD  linux-6.1.500/$EVIL  linux-6.1.500/" "$T/list-good.asc" > "$T/list-tampered.asc"
{ cat "$T/list-good.asc"; echo "$EVIL  linux-6.1.502.tar.xz"; } > "$T/list-appended.asc"
cp "$T/sums" "$T/list-unsigned.asc"

KORG_KEY=$T/trusted.asc
KORG_AUTOSIGNER=$TRUSTED
# expect NAME FILE VERSION PINNED  WANT(ok|changed|unchecked) [SHA]
expect() {
    KORG_SUMS_URL=file://$T/$2
    VERIFY_ERR= VERIFY_KIND= KSHA=
    if verify_kernel "$3" "$4"; then got=ok; else got=$VERIFY_KIND; fi
    if [ "$got" = "$5" ] && { [ -z "${6:-}" ] || [ "$KSHA" = "$6" ]; }; then
        pass "$1${VERIFY_ERR:+ ($VERIFY_ERR)}"
    else
        fail "$1: got $got${VERIFY_ERR:+ ($VERIFY_ERR)}, want $5"
    fi
}
expect "list signed by the trusted key is accepted" list-good.asc 6.1.500 "" ok "$GOOD"
expect "pinned checksum that matches is accepted" list-good.asc 6.1.500 "$GOOD" ok "$GOOD"
expect "pinned checksum that differs is refused" list-good.asc 6.1.500 "$EVIL" changed
expect "tampered list is refused" list-tampered.asc 6.1.500 "" changed
expect "list signed by another key is refused" list-other.asc 6.1.500 "" unchecked
expect "unsigned list is refused" list-unsigned.asc 6.1.500 "" changed
expect "a line added outside the signature is ignored" list-appended.asc 6.1.502 "" unchecked
expect "a version missing from the list is refused" list-good.asc 6.1.999 "" unchecked
expect "an unreachable list is reported as not checked" missing.asc 6.1.500 "" unchecked
KORG_KEY=$T/nokey.asc
expect "a missing trusted key is reported as not checked" list-good.asc 6.1.500 "" unchecked
KORG_KEY=$T/trusted.asc

# The pinned "other" key must not be accepted through the trusted file.
KORG_AUTOSIGNER=$OTHER
expect "the key file is not enough: the fingerprint must match" list-good.asc 6.1.500 "" unchecked
KORG_AUTOSIGNER=$TRUSTED

# Malware signatures: a pinned digest that differs from the published one.
if verify_rules 20261108 "$GOOD" 20261108 "$GOOD"; then pass "malware signatures with the published digest are accepted"; else fail "malware signatures: $VERIFY_ERR"; fi
if verify_rules 20261108 "$EVIL" 20261108 "$GOOD"; then fail "changed malware signatures were accepted"; elif [ "$VERIFY_KIND" = changed ]; then pass "changed malware signatures are refused"; else fail "changed malware signatures: kind $VERIFY_KIND"; fi
if verify_rules 20261108 "$GOOD" 20261200 ""; then fail "rules without a published digest were accepted"; else pass "rules without a published digest are refused"; fi

if [ "$fails" = 0 ]; then echo "UPDATE-VERIFY PASSED"; else echo "UPDATE-VERIFY FAILED ($fails)"; exit 1; fi
