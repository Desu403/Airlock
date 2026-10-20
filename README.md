# airlock

airlock is a viewer for files you don't trust. Every file you open gets its
own small virtual machine with no network card. The VM opens the file and
sends back pictures of the pages and cleaned-up text, and when you close the
file the VM is thrown away. Your computer never opens the document itself.

While you read, a second VM opens the same file next to a fake internet and
watches what it tries to do: start programs, download things, phone home,
drop files, exploit the reader. Then a third VM goes through the second
one's disk. You get a verdict in plain language (clean, suspicious or
malicious), the reasons behind it, and the technical evidence if you want it.

It runs on Linux (AppImage) and Windows 11 (installer).

## Why I built it

Everyone gets attachments they aren't sure about: an invoice they didn't
expect, a "shared document", a zip from someone they barely know. The usual
advice is "don't open it", which doesn't help when you actually need to read
it. Online scanners mean uploading your file to someone else. Desktop
antivirus only recognises what it has seen before.

I wanted something that lets you open the file anyway, with nothing at risk,
and tells you honestly what the file is.

## What it opens

| Kind | Files |
|---|---|
| Documents | PDF, Word, Excel, PowerPoint, OpenDocument, RTF |
| E-mail | .eml and Outlook .msg (attachments open in their own VM) |
| Archives | zip, 7z, rar, tar, gz, cab, iso (each file inside opens in its own VM) |
| Pictures | png, jpg, gif, webp, bmp, tiff, svg, heic, avif and a few more |
| Text and code | txt, md, json, html, js, py, c/cpp, ps1, vbs, bat and most other plain text, with syntax colours |

The real type is read from the file's contents inside the VM. Renaming
`invoice.exe` to `invoice.pdf` doesn't fool it.

## How well the malware check works

I don't trust numbers I can't reproduce, so there is a test bench
(`tests/bench.py`) with real files listed by hash. Every release has to pass
it before it ships. These are the numbers from the current version, with
the known-malware list switched off so that only airlock's own detection
counts:

| Set | Files | Result |
|---|---|---|
| Real malware (MalwareBazaar: documents, scripts, phishing pages) | 1,240 | 71% red, 91% flagged red or orange |
| Known document exploits (9 CVEs, Follina among them) | 177 | 176 red, none missed |
| Ordinary documents (Govdocs1, Apache POI test files, open-source code) | 2,562 | **0 false alarms**, 7% orange |

In normal use the score is higher, because airlock also checks every file
against 1.16 million known-malware fingerprints and every link against
URLhaus's list of active malware sites, all offline. The weak spot is
obfuscated scripts that do nothing until a real user is watching. More on
that below.

## How it keeps you safe

To get out, a malicious file would have to break through several walls, one
after another, each built from different code:

1. the program reading the file runs as an unprivileged user, and a monitor
   blocks and logs any attempt to start programs, open the network or
   attack the kernel. In the viewing VM, any attempt like that ends the
   session at once (the "tripwire")
2. a hardened Linux kernel with everything a document reader doesn't need
   removed
3. the hypervisor: Firecracker on Linux, QEMU with the Windows Hypervisor
   Platform on Windows
4. a jail around the hypervisor itself: a spare user ID, bubblewrap and
   seccomp on Linux, a Job object on Windows (no child processes, memory
   ceiling, no clipboard)
5. a strict, fuzzed protocol between the VM and the app: pictures, numbers
   and filtered text, nothing else. "Pixels only" mode switches the text off
   too

No sandbox is perfect. The goal is that escaping needs several unrelated
zero-days at once, plus a network that isn't there. The details are in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## How it got here

This took far longer than I expected, and most of the time went into
problems you never see in the finished app:

- **No root, no admin.** Running VMs normally means root. On Linux every VM
  runs as a spare user ID from your subuid range, the way rootless Podman
  does it, and setup asks for your password once. On Windows the installer
  works per user, and only turning on the hypervisor feature needs admin.
- **The viewer builds itself.** The AppImage doesn't ship a 1.6 GB image.
  On first run it builds the VM on your machine from pinned, checksummed
  downloads (Alpine, kernel.org, Firecracker), and every update is tested
  before it replaces the old one, with a rollback if anything fails.
- **False alarms.** A security tool that cries wolf gets ignored. Every
  detection is measured against thousands of ordinary files, and anything
  that flags a normal document doesn't ship. Some of the fixes were
  humbling: "facture" (French for invoice) matching inside "manufacture",
  or a book's author page looking like Microsoft phishing because the
  author writes about Windows.
- **Small things that took days.** The UI flickered on NVIDIA under
  Wayland until every blur and fade was removed. ClamAV's output arrived
  empty inside the VM until it was read from its log file instead. On
  Windows the VM took 11 seconds to boot until I found the kernel was
  wiping all its memory at start-up. Cutting that brought it to 1.4
  seconds.
- **Windows without rewriting it.** Everything inside the VM is shared
  between both systems. Only the part that starts the VM is different, and
  the same 42 test files give the same verdict on both.

## Getting it

**Linux:** download the AppImage from
[Releases](https://github.com/Desu403/Airlock/releases), make it executable
and run it. A setup screen checks your computer, fixes what it can and
builds the viewer (about 600 MB of downloads, 10 to 20 minutes, then about
2.4 GB on disk). It needs x86_64 with KVM.

**Windows:** run the installer from
[Releases](https://github.com/Desu403/Airlock/releases). It needs Windows 11
with the Windows Hypervisor Platform feature (Windows 10 should work but is
not tested yet); the installer offers to turn it on. About 1.9 GB on disk.

Building from source, the command-line tool, the per-user install script
and troubleshooting are in [docs/INSTALL.md](docs/INSTALL.md).

## Monthly updates

Malware changes every week, so a detection score from last month says less
every day. Once a month I:

1. add fresh malware samples from MalwareBazaar to the bench and rerun the
   whole thing, so detection gets measured against what is going around
   now, not last year
2. look at what was missed and fix what can be fixed without making
   anything else worse (zero false alarms is the rule)
3. update the readers inside the VM (MuPDF, LibreOffice and the rest) for
   security fixes
4. publish the release with its bench numbers in the release notes, so you
   can see whether it got better or worse

Between releases airlock updates its malware data by itself every day:
ClamAV signatures, the fingerprint list and the malware-site list.

## Roadmap

Next:

- **Updates inside the app.** airlock downloads and installs new versions
  itself from GitHub Releases, signed with a key only I hold, so you never
  have to fetch a new AppImage or installer by hand.
- **Small detection updates.** Split the VM into a big base (the readers,
  which rarely change) and a small airlock layer (the checks and rules,
  a few MB), so a detection fix is a quick download instead of a rebuild.
- **The fake internet on Windows,** so the Windows malware check sees
  network behaviour like the Linux one does.
- **A faster ClamAV.** Start each check from a saved VM that already has
  the signatures loaded, instead of loading 8 million of them every time.

Later:

- better detection for obfuscated scripts
- macOS (the VM side is ready; it needs a launcher for Apple's
  Virtualization framework)
- .deb and .rpm packages next to the AppImage
- opening Office macros in a real Windows VM, to watch them run

## Limits

- Signatures only name malware that is already known. Brand-new or targeted
  malware often matches nothing, which is why the behaviour checks come
  first, and why "no threats found" is never a guarantee.
- Malware that waits, or checks for a real user, may stay quiet in a VM
  that lives for a few seconds.
- The Windows malware check has no fake internet yet (see the roadmap).
- The VM image is large (about 1.6 GB), mostly because of LibreOffice.

## Licence

Not decided yet. Until there is a licence file, all rights are reserved:
you can read the code, but not reuse it.
