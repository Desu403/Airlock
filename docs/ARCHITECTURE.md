# airlock — architecture

Goal: read untrusted PDFs and Office documents without the document ever being
able to touch the host, and *see* what it tries to do.

## Principles

1. **The document never leaves the VM.** Only validated pixels come out.
2. **The host parses nothing the guest produces.** The wire format
   (`proto/`) is fixed 24-byte headers + a payload whose size is fully
   determined by validated fields. No strings, no nesting.
3. **Watch from outside.** A compromised guest can lie, so behaviour signals
   come from places the guest cannot control (VMM, sinkhole, disk diff).
4. **Escape = a chain of independent 0-days.** Every wall is a different
   technology, and there is no network to exfiltrate to.

## Walls (current)

| # | Wall | Status |
|---|------|--------|
| 1 | Renderer as `nobody`, `no_new_privs`, rlimits, timeout | done |
| 2 | Read-only root, tmpfs `noexec` work dir, VM destroyed after use | done |
| 3 | Firecracker microVM (KVM), no network device, vsock only | done |
| 4 | Firecracker built-in seccomp | done |
| 5 | bwrap around the VMM: all namespaces, no caps, near-empty FS | done |
| 6 | Strict host-side protocol state machine (+ tests) | done |
| 7 | Renderer under seccomp USER_NOTIF supervisor (x32 ABI killed) | done |
| 8 | Analysis network = private netns, sinkhole only, no route out | done |
| 9 | Sinkhole: no capabilities + seccomp allowlist (no open/exec/socket/connect) on all threads | done |
| 10 | Hardened guest kernel 6.1 LTS: no modules/BPF/io_uring/userns/IPv6/AF_PACKET/32-bit ABI, KASLR, init_on_alloc/free, panic on oops | done |
| 11 | Unexpected VM death (e.g. kernel panic) reported as an outside finding | done |
| 12 | VMM runs as a spare uid from the user's /etc/subuid range (a different one per VM; rootless equivalent of Firecracker's jailer); run dir granted to that uid only by ACL; sandbox built from file descriptors; no further user namespaces | done (falls back to the user's uid where unsupported — `airlock doctor` says so) |

## Roadmap

- **M2 — behaviour observation** — done (`airlock analyze`, `airlock selftest`)
  - sinkhole (`host/src/bin/sinkhole.rs`): VM NIC → tap0 in a private
    user+net namespace (no route out). Fake DNS, TCP catch-all via nft
    redirect (records original dst, HTTP request/Host, TLS SNI), packet log
    filtered to the guest MAC. Drops all capabilities after binding.
  - guest monitor (`guest-agent/src/monitor.rs`): seccomp USER_NOTIF.
    exec/fork/ptrace/kernel-surface syscalls denied + logged; inet sockets
    allowed + logged in analyze mode so the sinkhole sees where they go.
  - autopsy: the scratch disk is inspected by a second fresh VM (ro, noexec).
  - static PDF triage after `mutool clean -d` (defeats #xx-escaped names and
    object-stream hiding); JS bodies, URIs, Launch/OpenAction/AA/embedded.
  - report: findings grouped by *who saw it* (outside / in-VM / static),
    ATT&CK-mapped, verdict + `report.json`.
  - PDF JavaScript emulation (`guest-agent/src/harness.js`): QuickJS as
    nobody under the monitor, no network, against a fake Adobe Reader that
    claims to be exploitable 9.0 (so version-gated exploits fire). Real
    /Info and annotation strings are fed in (payload hiding spots). Logs API
    calls (launchURL, submitForm, exportDataObject+nLaunch, SOAP...), eval
    layers, %u shellcode, heap sprays, CVE triggers (2007-5659, 2008-2992,
    2009-0927/1492/1493/4324).
- **M3 — static triage / explainable risk report** (oletools, pcodedmp
  p-code vs source diff, pdfid, YARA) — runs *inside* a VM too
- **M4 — Office documents** — done. Content sniffing (OLE2/OOXML/ODF/RTF,
  never the extension). Static: oletools inside the VM (VBA source, AutoExec,
  suspicious keywords, IOCs, **VBA stomping via pcodedmp**, XLM), external
  relationships (remote template, Follina `mhtml:`/`ms-msdt`), DDE fields,
  RTF objects (Equation Editor, OLE2Link). Render: LibreOffice headless as
  nobody under the monitor with a prebuilt profile; macros never run. Known
  LibreOffice start-up probes (paperconf, gpgconf) are denied silently by
  exact match; everything else is reported. Autopsy diffs the profile against
  the pristine template (macro persistence).
- **Regression suite**: `tests/run.sh` (fixtures: `tests/mkpdf.py`,
  `tests/fetch-fixtures.sh`) — expected verdict per sample + selftest.
- **M5 — live interactive viewing** — done (`host/src/live.rs`,
  `guest-agent/src/live.rs`). The VM stays up (no NIC) and answers
  Render{page,dpi} / Search{query} / GetText{page} / GetLayout{page}. One
  `mutool -F stext` pass gives page sizes + glyph boxes; search returns
  **only rectangles** (numbers), the host draws highlights. GetLayout returns
  one box per text line (numbers) plus the page text, which the app lays
  over the page image as an invisible, selectable layer (copy is forced to
  plain text). Page text is the single text channel: size-capped, then
  re-sanitised on the host (controls + bidi overrides removed — "Trojan
  Source").
- **M6 — Tauri desktop app** — `app/`. Webview receives PNGs encoded by Rust
  from validated pixels, numbers and sanitised text (inserted via
  textContent only). Strict CSP, no remote content, capabilities =
  core:default. File dialog and drag-and-drop hand Rust a *path*; the
  webview never reads document bytes. Analyze runs in separate VMs while
  viewing continues.
- **M7 — hardening** — partly done: sinkhole seccomp, hardened guest kernel
  (`guest/build-kernel.sh`, fragment `guest/kernel-hardening.config`),
  VM-death detection, spare-uid VMM (wall 12; replaces the jailer, which
  must be started as root for every VM). Open: Landlock + seccomp on the
  host process, fuzzing the protocol, gVisor inside the guest.
  PERF_EVENTS cannot be disabled on x86; the renderer monitor denies it.
- **Phase 2 — Windows detonation**: QEMU/KVM Windows guest with real Office,
  snapshot revert, sinkhole, time acceleration, out-of-VM introspection

## Layout

- `proto/` — shared wire format (no_std, tested)
- `guest-agent/` — PID 1 in the VM (static musl)
- `guest/build-rootfs.sh` — rootless guest image build
- `host/` — `airlock` CLI
- `vendor/` — Firecracker + guest kernel (downloaded, checksummed; gitignored)
