#!/bin/sh
# Builds dist/airlock-<version>-x86_64.AppImage: the desktop app (WebKitGTK
# bundled), the CLI and the sinkhole, plus the build kit its first-run setup
# uses to check the computer and build the VM (scripts/setup.sh). The VM
# image itself is not inside: it is built on the user's machine from pinned,
# checksum-verified downloads (so the AppImage stays small and every install
# can update itself).
#
# Needs: cargo, and tauri-cli (cargo install tauri-cli --version '^2').
set -eu
cd "$(dirname "$0")/.."
command -v cargo-tauri >/dev/null || PATH=$HOME/.cargo/bin:$PATH
command -v cargo-tauri >/dev/null || { echo "needs tauri-cli: cargo install tauri-cli --version '^2'" >&2; exit 1; }

(cd host && cargo build --release -q)
STAGE=app/bundle-stage
rm -rf "$STAGE"
mkdir -p "$STAGE/kit" "$STAGE/bin"
git ls-files guest guest-agent proto scripts tests | while read -r f; do install -D -m "$(stat -c %a "$f")" "$f" "$STAGE/kit/$f"; done
touch "$STAGE/kit/.airlock-kit"
# Two fingerprints: .vm-version covers what goes into the VM (guest, agent,
# protocol, pinned versions): a newer AppImage offers a viewer rebuild only
# when it changed. .kit-version covers every kit file: the installed kit is
# refreshed when it changed (new update scripts reach existing installs).
git ls-files guest guest-agent proto scripts/bootstrap.sh | sort | xargs sha256sum | sha256sum | cut -c1-12 > "$STAGE/kit/.vm-version"
(cd "$STAGE/kit" && find . -type f ! -name .kit-version | sort | xargs sha256sum | sha256sum | cut -c1-12) > "$STAGE/kit/.kit-version"
install -m 0755 host/target/release/airlock host/target/release/sinkhole "$STAGE/bin/"

# Signed for the in-app updater when the key is there (scripts/release.sh
# sets it); AIRLOCK_EXTRA_CONFIG: one more tauri config, for tests only.
set -- --config tauri.appimage.json
[ -n "${AIRLOCK_EXTRA_CONFIG:-}" ] && set -- "$@" --config "$AIRLOCK_EXTRA_CONFIG"
rm -f app/target/release/bundle/appimage/*.AppImage app/target/release/bundle/appimage/*.AppImage.sig
if [ -z "${TAURI_SIGNING_PRIVATE_KEY:-}" ]; then
    # Without the key tauri cannot write the updater signature: plain build.
    printf '{"bundle":{"createUpdaterArtifacts":false}}' > app/target/no-updater-sig.json
    set -- "$@" --config target/no-updater-sig.json
fi
(cd app && cargo tauri build --bundles appimage "$@")
mkdir -p dist
VERSION=$(sed -n 's/^  "version": "\(.*\)",/\1/p' app/tauri.conf.json)
VERSION=${AIRLOCK_VERSION:-$VERSION}
cp app/target/release/bundle/appimage/*.AppImage "dist/airlock-$VERSION-x86_64.AppImage"
rm -f "dist/airlock-$VERSION-x86_64.AppImage.sig"
for s in app/target/release/bundle/appimage/*.AppImage.sig; do [ -f "$s" ] && cp "$s" "dist/airlock-$VERSION-x86_64.AppImage.sig"; done
ls -lh "dist/airlock-$VERSION-x86_64.AppImage"
