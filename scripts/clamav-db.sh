#!/bin/sh
# ClamAV's signature database (Cisco Talos, signed .cvd files) for the
# analysis VM: downloaded only when changed, packed into a read-only disk
# (DIR/clamav.ext4) that the analysis VM mounts. The VM image itself never
# holds it: the database changes several times a day.
#
#   scripts/clamav-db.sh DIR
set -eu
DIR=$1
shift || true
DB=$DIR/clamav
STATUS=$DIR/clamav.status
mkdir -p "$DB"
# At most every 12 hours (the database changes a few times a day; the
# server limits clients that ask too often).
if [ -f "$STATUS" ] && [ -f "$DIR/clamav.ext4" ] && [ -n "$(find "$STATUS" -mmin -720 2>/dev/null)" ] && [ "${1:-}" != --force ]; then
    exit 0
fi
UA="ClamAV/1.4.6 (OS: linux-gnu, ARCH: x86_64, CPU: x86_64; airlock)"
changed=0
refused=0
for f in main.cvd daily.cvd bytecode.cvd; do
    # -z: only when newer than the copy we have (a "not changed" answer is tiny).
    if [ -f "$DB/$f" ]; then set -- -z "$DB/$f"; else set --; fi
    code=$(curl -sSL -m 600 -A "$UA" "$@" -o "$DB/$f.part" -w '%{http_code}' "https://database.clamav.net/$f" || true)
    case $code in 200 | 304) ;; *) rm -f "$DB/$f.part"; [ "$code" = 429 ] && refused=1; continue ;; esac
    if [ -s "$DB/$f.part" ]; then
        # A .cvd starts with "ClamAV-VDB:"; anything else (an error page) is dropped.
        if head -c 11 "$DB/$f.part" | grep -q '^ClamAV-VDB:'; then mv -f "$DB/$f.part" "$DB/$f"; changed=1; else rm -f "$DB/$f.part"; fi
    else
        rm -f "$DB/$f.part"
    fi
done
# What About airlock shows: "<unix time> ok|refused|missing".
if [ ! -f "$DB/main.cvd" ] || [ ! -f "$DB/daily.cvd" ]; then
    echo "$(date +%s) missing" > "$STATUS"
    echo "ClamAV database not available" >&2
    exit 1
fi
if [ "$refused" = 1 ]; then echo "$(date +%s) refused" > "$STATUS"; else echo "$(date +%s) ok" > "$STATUS"; fi
if [ "$changed" = 1 ] || [ ! -f "$DIR/clamav.ext4" ]; then
    # The signatures are verified by ClamAV itself when it loads them (signed by Talos).
    mb=$(( $(du -sm "$DB" | cut -f1) * 12 / 10 + 16 ))
    rm -f "$DIR/clamav.ext4.new"
    mke2fs -q -t ext4 -L airlock-clamav -O ^has_journal -d "$DB" "$DIR/clamav.ext4.new" "${mb}M"
    chmod 0644 "$DIR/clamav.ext4.new"
    mv -f "$DIR/clamav.ext4.new" "$DIR/clamav.ext4"
fi
echo "ClamAV database: $(head -c 100 "$DB/daily.cvd" | cut -d: -f3) (daily version)"
