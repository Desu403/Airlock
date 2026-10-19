#!/bin/sh
# ClamAV's signature database (Cisco Talos, signed .cvd files) for the
# analysis VM: downloaded only when changed, packed into a read-only disk
# (DIR/clamav.ext4) that the analysis VM mounts. The VM image itself never
# holds it: the database changes several times a day.
#
#   scripts/clamav-db.sh DIR
set -eu
DIR=$1
DB=$DIR/clamav
mkdir -p "$DB"
UA="ClamAV/1.4.6 (OS: linux-gnu, ARCH: x86_64, CPU: x86_64; airlock)"
changed=0
for f in main.cvd daily.cvd bytecode.cvd; do
    # -z: only when newer than the copy we have.
    if [ -f "$DB/$f" ]; then set -- -z "$DB/$f"; else set --; fi
    curl -fsSL -m 600 -A "$UA" "$@" -o "$DB/$f.part" "https://database.clamav.net/$f" || { rm -f "$DB/$f.part"; continue; }
    if [ -s "$DB/$f.part" ]; then
        # A .cvd starts with "ClamAV-VDB:"; anything else (an error page) is dropped.
        if head -c 11 "$DB/$f.part" | grep -q '^ClamAV-VDB:'; then mv -f "$DB/$f.part" "$DB/$f"; changed=1; else rm -f "$DB/$f.part"; fi
    else
        rm -f "$DB/$f.part"
    fi
done
[ -f "$DB/main.cvd" ] && [ -f "$DB/daily.cvd" ] || { echo "ClamAV database not available" >&2; exit 1; }
if [ "$changed" = 1 ] || [ ! -f "$DIR/clamav.ext4" ]; then
    # The signatures are verified by ClamAV itself when it loads them (signed by Talos).
    mb=$(( $(du -sm "$DB" | cut -f1) * 12 / 10 + 16 ))
    rm -f "$DIR/clamav.ext4.new"
    mke2fs -q -t ext4 -L airlock-clamav -O ^has_journal -d "$DB" "$DIR/clamav.ext4.new" "${mb}M"
    chmod 0644 "$DIR/clamav.ext4.new"
    mv -f "$DIR/clamav.ext4.new" "$DIR/clamav.ext4"
fi
echo "ClamAV database: $(head -c 100 "$DB/daily.cvd" | cut -d: -f3) (daily version)"
