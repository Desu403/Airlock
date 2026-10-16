#!/bin/sh
# Installs airlock for the current user, no root: binaries in ~/.local/bin,
# VM assets in ~/.local/lib/airlock, a desktop launcher, and "Open with
# airlock" for PDF and Office files. Run scripts/bootstrap.sh first.
#
#   scripts/install.sh              install / update
#   scripts/install.sh --default    ... and make airlock the default app for
#                                   those files
#   A plain install changes no defaults: whatever opens each file type now
#   is pinned first (a new launcher would otherwise win the fallback lookup).
#   --uninstall restores the exact previous state.
#   scripts/install.sh --uninstall  remove everything, restore defaults
#   --prefix DIR                    install under DIR instead of ~/.local
set -eu
cd "$(dirname "$0")/.."

PREFIX=$HOME/.local
MODE=install
DEFAULT=0
while [ $# -gt 0 ]; do
    case "$1" in
        --default) DEFAULT=1 ;;
        --uninstall) MODE=uninstall ;;
        --prefix) PREFIX=$2; shift ;;
        *) echo "usage: $0 [--default] [--uninstall] [--prefix DIR]" >&2; exit 2 ;;
    esac
    shift
done

BIN=$PREFIX/bin
LIB=$PREFIX/lib/airlock
DATA=${XDG_DATA_HOME:-$HOME/.local/share}
DESKTOP=$DATA/applications/airlock.desktop
ICON=$DATA/icons/hicolor/512x512/apps/airlock.png
MIMEAPPS=${XDG_CONFIG_HOME:-$HOME/.config}/mimeapps.list
# One line per type: "<type> <explicit default or -> <effective default or ->",
# recorded on first install.
DEFAULTS=$LIB/previous-defaults
# Everything airlock can open (type is still sniffed from content inside the VM).
TYPES="application/pdf
application/msword
application/vnd.openxmlformats-officedocument.wordprocessingml.document
application/vnd.ms-word.document.macroEnabled.12
application/vnd.ms-excel
application/vnd.openxmlformats-officedocument.spreadsheetml.sheet
application/vnd.ms-excel.sheet.macroEnabled.12
application/vnd.ms-powerpoint
application/vnd.openxmlformats-officedocument.presentationml.presentation
application/vnd.ms-powerpoint.presentation.macroEnabled.12
application/vnd.oasis.opendocument.text
application/vnd.oasis.opendocument.spreadsheet
application/vnd.oasis.opendocument.presentation
application/rtf
text/rtf"

die() { echo "error: $*" >&2; exit 1; }
refresh() {
    command -v update-desktop-database >/dev/null && update-desktop-database -q "$DATA/applications" 2>/dev/null || true
    command -v gtk-update-icon-cache >/dev/null && gtk-update-icon-cache -q -t "$DATA/icons/hicolor" 2>/dev/null || true
}

explicit_default() {
    [ -f "$MIMEAPPS" ] || return 0
    sed -n '/^\[Default Applications\]/,/^\[/p' "$MIMEAPPS" | sed -n "s|^$1=\([^;]*\).*|\1|p" | head -1
}

drop_default() {
    [ -f "$MIMEAPPS" ] && sed -i "\|^$1=$2;*\$|d" "$MIMEAPPS"
    return 0
}

# Records the current state, then pins today's effective defaults so the
# new launcher does not silently take over.
pin_defaults() {
    [ -f "$DEFAULTS" ] && return 0
    mkdir -p "$LIB"
    for type in $TYPES; do
        explicit=$(explicit_default "$type")
        effective=$(xdg-mime query default "$type" 2>/dev/null || true)
        echo "$type ${explicit:--} ${effective:--}" >> "$DEFAULTS"
        if [ -z "$explicit" ] && [ -n "$effective" ]; then
            xdg-mime default "$effective" "$type"
        fi
    done
}

restore_defaults() {
    [ -f "$DEFAULTS" ] || return 0
    while read -r type explicit effective; do
        current=$(explicit_default "$type")
        if [ "$explicit" = - ]; then
            # We added the line (a pin or airlock): remove it.
            case "$current" in airlock.desktop|"$effective") drop_default "$type" "$current" ;; esac
        elif [ "$current" = airlock.desktop ]; then
            xdg-mime default "$explicit" "$type"
        fi
    done < "$DEFAULTS"
    rm -f "$DEFAULTS"
    echo "restored previous default apps"
}

if [ "$MODE" = uninstall ]; then
    restore_defaults
    rm -f "$BIN/airlock" "$BIN/airlock-app" "$DESKTOP" "$ICON"
    rm -rf "$LIB"
    refresh
    echo "airlock uninstalled"
    exit 0
fi

# --- install -----------------------------------------------------------------
for f in host/target/release/airlock host/target/release/sinkhole vendor/bin/firecracker build/rootfs.ext4; do
    [ -f "$f" ] || die "missing $f — run scripts/bootstrap.sh first"
done
# Never install a VM without the hardened guest kernel.
[ -f vendor/bin/vmlinux-airlock ] || die "missing vendor/bin/vmlinux-airlock — run guest/build-kernel.sh"
APP=0
[ -f app/target/release/airlock-app ] && APP=1

mkdir -p "$BIN" "$LIB"
install -m 0755 host/target/release/airlock "$BIN/airlock"
install -m 0755 host/target/release/sinkhole "$LIB/sinkhole"
install -m 0755 vendor/bin/firecracker "$LIB/firecracker"
install -m 0644 vendor/bin/vmlinux-airlock "$LIB/vmlinux"
# Copy then rename: VMs already running keep their old image.
cp --reflink=auto --sparse=always build/rootfs.ext4 "$LIB/rootfs.ext4.new"
chmod 0644 "$LIB/rootfs.ext4.new"
mv -f "$LIB/rootfs.ext4.new" "$LIB/rootfs.ext4"
echo "installed CLI:  $BIN/airlock"

if [ "$APP" = 1 ]; then
    command -v xdg-mime >/dev/null && pin_defaults
    install -m 0755 app/target/release/airlock-app "$BIN/airlock-app"
    install -D -m 0644 app/icons/icon.png "$ICON"
    mkdir -p "$(dirname "$DESKTOP")"
    cat > "$DESKTOP" <<EOF
[Desktop Entry]
Type=Application
Name=airlock
GenericName=Safe Document Viewer
Comment=Open untrusted PDFs and Office files inside a disposable microVM
Exec="$BIN/airlock-app" %f
Icon=airlock
Terminal=false
Categories=Office;Viewer;Security;
Keywords=pdf;docx;malware;sandbox;safe;
MimeType=$(echo "$TYPES" | tr '\n' ';');
StartupWMClass=airlock-app
EOF
    refresh
    echo "installed app:  $BIN/airlock-app (launcher: airlock; 'Open with airlock' for PDF and Office files)"
else
    echo "desktop app not built — skipped (scripts/bootstrap.sh without --no-app builds it)"
fi

if [ "$DEFAULT" = 1 ]; then
    [ "$APP" = 1 ] || die "--default needs the desktop app"
    for type in $TYPES; do
        xdg-mime default airlock.desktop "$type"
    done
    echo "airlock is now the default app for PDF and Office files (undo: $0 --uninstall)"
fi

case ":$PATH:" in *":$BIN:"*) ;; *) echo "note: $BIN is not in your PATH" ;; esac
echo
"$BIN/airlock" doctor
