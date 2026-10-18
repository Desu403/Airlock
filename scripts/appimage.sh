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

(cd app && cargo tauri build --bundles appimage --config tauri.appimage.json)
mkdir -p dist
VERSION=$(sed -n 's/^  "version": "\(.*\)",/\1/p' app/tauri.conf.json)
cp app/target/release/bundle/appimage/*.AppImage "dist/airlock-$VERSION-x86_64.AppImage"
ls -lh "dist/airlock-$VERSION-x86_64.AppImage"
