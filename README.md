# airlock

Open PDFs and Office documents you don't trust — and see what they try to do.

airlock opens every document inside a disposable **Firecracker microVM**
(hardware virtualisation via KVM). Your computer never parses the document:
it only receives validated pixels, numbers and cleaned text. When you close
the document, the VM is destroyed.

- **View** — read, zoom, search and copy text while the file stays sealed in
  a VM with **no network card**.
- **Analyze** — detonate the file in a VM wired to a **fake internet** and
  report what it tries to do: contact servers, run programs, drop files,
  exploit the reader. Findings are grouped by *who saw them* (outside the VM,
  in-VM monitor, JavaScript emulation, static structure) and mapped to
  MITRE ATT&CK.

Supported: PDF, DOC/DOCX, XLS/XLSX, PPT/PPTX, ODT/ODS/ODP, RTF (type is
detected from content, never from the file name).

## How it protects you

An attacker needs a chain of independent exploits, and even then has no
network to send anything to:

1. renderer runs as `nobody` under a seccomp supervisor (exec/fork/ptrace/
   kernel-attack syscalls blocked and logged)
2. hardened guest kernel (no modules, BPF, io_uring, user namespaces, IPv6,
   raw sockets; panics on any oops)
3. Firecracker VMM (minimal Rust device model, its own seccomp)
4. bubblewrap jail around the VMM (all namespaces, no capabilities),
   running as a **spare user ID** that owns nothing on your system (from
   your `/etc/subuid` range, like rootless Podman — no root needed)
5. a strict, tested host protocol: fixed-size headers, pixels and numbers;
   the only text channel is size-capped and sanitised
6. the fake-internet process is jailed, capability-less and seccomp-locked

Details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). No sandbox is
perfect; airlock's goal is to make escape require several unrelated 0-days.

## Requirements

- Linux on **x86_64** with KVM (`/dev/kvm` readable/writable — usually the
  `kvm` group)
- unprivileged user namespaces (default on Arch, Fedora, Debian 11+; see
  Troubleshooting for Ubuntu 24.04+)
- ~6 GB free disk, ~15 minutes for the first build; no root needed

Packages:

| Distro | Command |
|---|---|
| Arch | `sudo pacman -S --needed rust bubblewrap iproute2 nftables util-linux e2fsprogs curl xz python file webkit2gtk-4.1 gtk3 libsoup3 librsvg` |
| Debian 12 / Ubuntu 24.04 | `sudo apt install bubblewrap iproute2 nftables util-linux e2fsprogs curl xz-utils python3 file build-essential pkg-config libwebkit2gtk-4.1-dev libgtk-3-dev libsoup-3.0-dev librsvg2-dev` and Rust via [rustup](https://rustup.rs) (distro Rust is too old) |
| Fedora | `sudo dnf install rust cargo bubblewrap iproute nftables util-linux e2fsprogs curl xz python3 file webkit2gtk4.1-devel gtk3-devel libsoup3-devel librsvg2-devel` |

The webkit/gtk packages are only needed for the desktop app
(`--no-app` skips it).

## Setup

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

## Usage

```sh
app/target/release/airlock-app [file]           # desktop app (drag & drop works)

host/target/release/airlock view file.pdf       # safe copy: file.airlock/safe.pdf + PNGs
host/target/release/airlock analyze file.docx   # behaviour report + report.json
host/target/release/airlock selftest            # prove every detector fires
host/target/release/airlock doctor              # check this machine
```

`safe.pdf` contains only images of the pages — no scripts, links, forms,
fonts or embedded files survive.

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

## Status and limits

Working: view (live), analyze, PDF JavaScript emulation, Office static
triage (VBA incl. stomping, XLM, DDE, Follina, remote templates, RTF
exploits), desktop app, regression suite (`tests/run.sh`).

Not yet: packaged installers (run from the source tree for now), Windows
and macOS hosts, executing Office macros (needs a Windows guest — planned). The guest image is
~1.1 GB because of LibreOffice.

Guest packages (MuPDF, LibreOffice, …) come from Alpine's 3.24 branch at
build time, so rebuilding the image (`guest/build-rootfs.sh`) picks up
their security updates.
