# Installing and running airlock

The short version is in the [README](../README.md). This page has the
details: requirements, building from source, the per-user install, updates
and troubleshooting.

## Windows

Windows 11, 64-bit (Windows 10 should work but is not tested yet), with the **Windows Hypervisor Platform** feature.
Run `airlock-<version>-windows-x64-setup.exe`. It installs for your user
only (no administrator rights) into `%LOCALAPPDATA%\airlock`, adds a Start
menu entry and "Open with airlock" for PDF, Office and e-mail files, and an
uninstaller (Settings > Apps). If the hypervisor feature is off, the
installer offers to turn it on (this one step asks for administrator
permission, then a restart).

The Windows build is made on Linux: `scripts/windows.sh` cross-compiles the
app and CLI (cargo-xwin), bundles QEMU for Windows (pinned and
checksum-verified), the same hardened kernel and VM image as on Linux, and
packs it with NSIS under Wine.

## Requirements

- Linux on **x86_64** with KVM (`/dev/kvm` readable/writable — usually the
  `kvm` group)
- unprivileged user namespaces (default on Arch, Fedora, Debian 11+; see
  Troubleshooting for Ubuntu 24.04+)
- ~6 GB free disk, ~15 minutes for the first build; no root needed

Packages:

| Distro | Command |
|---|---|
| Arch | `sudo pacman -S --needed rust bubblewrap iproute2 nftables util-linux e2fsprogs curl xz python file xdg-dbus-proxy webkit2gtk-4.1 gtk3 libsoup3 librsvg` |
| Debian 12 / Ubuntu 24.04 | `sudo apt install bubblewrap iproute2 nftables util-linux e2fsprogs curl xz-utils python3 file xdg-dbus-proxy build-essential pkg-config libwebkit2gtk-4.1-dev libgtk-3-dev libsoup-3.0-dev librsvg2-dev` and Rust via [rustup](https://rustup.rs) (distro Rust is too old) |
| Fedora | `sudo dnf install rust cargo bubblewrap iproute nftables util-linux e2fsprogs curl xz python3 file xdg-dbus-proxy webkit2gtk4.1-devel gtk3-devel libsoup3-devel librsvg2-devel` |

The webkit/gtk packages and `xdg-dbus-proxy` are only needed for the
desktop app (`--no-app` skips it). The app runs its web view in WebKit's
own bubblewrap + seccomp sandbox, with an airlock-only cache directory.

## Setup

**AppImage** (`scripts/appimage.sh` builds `dist/airlock-*.AppImage`): run it;
a setup screen checks the computer, fixes what needs root with one password
prompt, and builds the VM in your user account (about 600 MB of pinned,
checksum-verified downloads, 10-20 minutes). The same steps by hand:
`scripts/setup.sh check | plan | fix | build`.

**From source:**

```sh
git clone <this repo> airlock && cd airlock
scripts/bootstrap.sh            # fetch pinned + checksummed inputs, build everything
host/target/release/airlock doctor
host/target/release/airlock selftest
```

`bootstrap.sh` downloads exact, SHA-256-pinned versions of Firecracker,
the Alpine root filesystem and the Linux kernel source, builds a hardened
guest kernel and the guest image without root, then builds the CLI and app.
Add `--tests` to also run the regression suite.

## Install

```sh
scripts/install.sh              # for your user, no root: ~/.local/bin + launcher
scripts/install.sh --default    # ... and open PDF/Office files with airlock by default
scripts/install.sh --uninstall  # remove, and restore your previous default apps
```

The installer puts `airlock` and `airlock-app` in `~/.local/bin`, the VM
image and kernel in `~/.local/lib/airlock`, and adds an **airlock** launcher
with "Open with airlock" for PDF and Office files. A plain install changes
none of your default apps. Re-run it after rebuilding to update.

## Keeping it up to date

The realistic risk for any viewer is running old renderers with known bugs.
Run this every few weeks (`airlock doctor` warns once the VM image is more
than 30 days old):

```sh
scripts/update.sh            # newest guest packages, 6.1 LTS kernel, Firecracker, YARA rules
scripts/update.sh --check    # just show what is out of date
scripts/update.sh --rollback # back to the version before the last update
scripts/update.sh --status   # machine-readable check (used by the app)
```

`scripts/install.sh` also installs a small **update kit**, so an installed
airlock updates itself from the official servers (Alpine, kernel.org,
Firecracker's releases) with no source checkout and no compilers: the build
runs in a throwaway Alpine build root (`~/.local/lib/airlock/kit/scripts/update.sh`;
the kit keeps ~2 GB: a build cache and the previous version for rollback).

The desktop app does the same from its **Updates** button: once a day it
checks kernel.org, GitHub and Alpine's mirror (this can be switched off in
the Updates panel), pops up a notice when security fixes are out (e.g. a new
MuPDF) and, unless switched off, installs them in the background and tells
you afterwards.

New kernels are verified against kernel.org's GPG-signed checksums,
Firecracker, Alpine and the YARA-Forge rules against their published
checksums. The working
version is kept aside and the full regression suite must pass before the new
one is used; otherwise the old one is restored. An installed copy is
updated too.

## Usage

```sh
airlock-app [files...]       # desktop app (drag & drop works)

airlock view file.pdf        # safe copy: file.airlock/safe.pdf + PNGs
airlock analyze file.docx    # behaviour report + report.json
airlock selftest             # prove every detector fires
airlock doctor               # check this machine
```

Without installing, run them from the source tree:
`app/target/release/airlock-app`, `host/target/release/airlock`.

`safe.pdf` contains only images of the pages — no scripts, links, forms,
fonts or embedded files survive.

In the app:

- **Save ▸ Safe PDF copy** (Ctrl+S) writes that same kind of pixels-only
  PDF, safe to keep, share or open in any reader.
- **Save ▸ Print** (Ctrl+P) prints the pixels the VM drew.
- **Save report…** in the analysis panel exports the report as text (or
  `.json` for tools).
- Opening or dropping several files opens each in **its own window, with
  its own VM**: documents never share a renderer.

## Troubleshooting

- **`/dev/kvm` access** — enable VT-x/AMD-V in firmware, then
  `sudo usermod -aG kvm $USER` and log in again.
- **User namespaces blocked (Ubuntu 24.04+)** — Ubuntu restricts them via
  AppArmor. Either `sudo sysctl kernel.apparmor_restrict_unprivileged_userns=0`
  or install an AppArmor profile that grants `userns` to `bwrap`.
- **Debian older kernels** — `sudo sysctl kernel.unprivileged_userns_clone=1`.
- **"VMs run as your own uid" (doctor warning)** — airlock still works, minus
  one wall. Give your user a spare ID range:
  `sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 $USER`,
  and make sure `/dev/kvm` and `/dev/net/tun` are mode 0666 (systemd's
  default).
- **Anything else** — run `airlock doctor`; each failed check prints a fix.
  `-v` on any command prints the (sanitised) VM console.

