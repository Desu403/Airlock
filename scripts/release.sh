#!/bin/sh
# Builds a release: the Linux AppImage and the Windows installer, both signed
# with the update key (~/.config/airlock/updater.key, never in the repo), and
# latest.json, the file every installed airlock checks for new versions.
# Everything lands in dist/release/v<version>/.
#
#   scripts/release.sh                 build and sign only
#   scripts/release.sh --publish       ... then create the GitHub release
#                                      v<version> and upload everything
#
# Run it only on a version that passed the release gate. Publishing needs a
# GitHub token with access to the repo (the one git uses for github.com).
set -eu
cd "$(dirname "$0")/.."
REPO=Desu403/Airlock
KEY=${AIRLOCK_UPDATE_KEY:-$HOME/.config/airlock/updater.key}
[ -f "$KEY" ] || { echo "no update key at $KEY" >&2; exit 1; }
VERSION=${AIRLOCK_VERSION:-$(sed -n 's/^  "version": "\(.*\)",/\1/p' app/tauri.conf.json)}
NOTES=${AIRLOCK_NOTES:-"See the release page for what changed."}
BASE_URL=${AIRLOCK_RELEASE_URL:-https://github.com/$REPO/releases/download/v$VERSION}
OUT=dist/release/v$VERSION

TAURI_SIGNING_PRIVATE_KEY=$(cat "$KEY")
TAURI_SIGNING_PRIVATE_KEY_PASSWORD=""
export TAURI_SIGNING_PRIVATE_KEY TAURI_SIGNING_PRIVATE_KEY_PASSWORD AIRLOCK_VERSION=$VERSION

if [ "${AIRLOCK_SKIP_BUILD:-}" != 1 ]; then
    scripts/appimage.sh
    [ "${AIRLOCK_LINUX_ONLY:-}" = 1 ] || scripts/windows.sh
fi
rm -rf "$OUT"
mkdir -p "$OUT"
L=airlock-$VERSION-x86_64.AppImage
W=airlock-$VERSION-windows-x64-setup.exe
cp "dist/$L" "dist/$L.sig" "$OUT/"
[ -f "dist/$W" ] && cp "dist/$W" "dist/$W.sig" "$OUT/"

python3 -I - "$OUT" "$VERSION" "$BASE_URL" "$NOTES" "$L" "$W" <<'EOF'
import datetime, json, os, sys
out, version, base, notes, linux, windows = sys.argv[1:]
def sig(name):
    with open(os.path.join(out, name + ".sig")) as f:
        return f.read().strip()
platforms = {"linux-x86_64": {"signature": sig(linux), "url": f"{base}/{linux}"}}
if os.path.exists(os.path.join(out, windows)):
    platforms["windows-x86_64"] = {"signature": sig(windows), "url": f"{base}/{windows}"}
latest = {
    "version": version,
    "notes": notes,
    "pub_date": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "platforms": platforms,
}
with open(os.path.join(out, "latest.json"), "w") as f:
    json.dump(latest, f, indent=2)
print("latest.json:", ", ".join(platforms))
EOF
(cd "$OUT" && sha256sum airlock-* > SHA256SUMS)
ls -lh "$OUT"

[ "${1:-}" = --publish ] || { echo "built in $OUT (not published: run with --publish)"; exit 0; }

# The release points at this commit: GitHub must have it first.
git push origin HEAD
# The token git already uses for github.com.
TOKEN=$(printf 'protocol=https\nhost=github.com\n\n' | git credential fill 2>/dev/null | sed -n 's/^password=//p')
[ -n "$TOKEN" ] || { echo "no GitHub token found for github.com" >&2; exit 1; }
api() { curl -fsS -H "Authorization: Bearer $TOKEN" -H "Accept: application/vnd.github+json" "$@"; }
body=$(python3 -I -c 'import json,sys; print(json.dumps({"tag_name": "v"+sys.argv[1], "target_commitish": sys.argv[2], "name": "airlock "+sys.argv[1], "body": sys.argv[3]}))' "$VERSION" "$(git rev-parse HEAD)" "$NOTES")
id=$(api -X POST "https://api.github.com/repos/$REPO/releases" -d "$body" | python3 -I -c 'import json,sys; print(json.load(sys.stdin)["id"])')
for f in "$OUT"/*; do
    n=$(basename "$f")
    api -X POST -H "Content-Type: application/octet-stream" --data-binary @"$f" "https://uploads.github.com/repos/$REPO/releases/$id/assets?name=$n" > /dev/null
    echo "uploaded $n"
done
echo "published https://github.com/$REPO/releases/tag/v$VERSION"
