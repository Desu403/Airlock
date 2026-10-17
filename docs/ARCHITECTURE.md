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
| 13 | Page text and file names narrowed to plain visible characters before any UI; optional pixels-only mode | done |
| 14 | Every host-side parser fuzzed with hostile streams (`cargo test`; `AIRLOCK_FUZZ_ITERS` for long runs) | done |
| 15 | App web view (where text is drawn) in WebKitGTK's bubblewrap + seccomp sandbox (forced on), own data dir, airlock-only cache dir — no home, no `.ssh`, no capabilities | done |
| 16 | Staying patched: `scripts/update.sh` rebuilds the guest with current security fixes (base system too) and moves to the newest 6.1 LTS kernel (kernel.org GPG-signed checksums) / Firecracker / Alpine point release; regression suite gates the switch, automatic restore on failure; doctor warns when the image is >30 days old (`rootfs.info`: build date + package versions) | done |

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
- **YARA signatures** — done (`guest-agent/src/yara.rs`). YARA-Forge's
  "core" package (pinned release + SHA-256, ~5,000 rules) is compiled into
  the image at build time (`yarac`); `guest/yara_meta.py` keeps each rule's
  score, description and author, since yara prints only names. Scanned, as
  nobody under the monitor without network: the file, the decompressed PDF,
  and for Office files every ZIP part, OLE stream, OLE package and macro's
  source (`guest/unpack.py`, bounded; written to a tmpfs so the autopsy
  only ever sees what the document left). The autopsy VM scans dropped
  files too (selftest: a dropped EICAR file must be named). Severity from
  the rule's score (>=75 high, decisive; 60-74 medium); technique rules
  (`SUSP_`, `INDICATOR_`, `GEN_`, ...) are capped at medium. The larger
  "extended" package was tried and rejected: it named a criminal group
  (TA505) on two harmless Atomic Red Team files.
- **M4 — Office documents** — done. Content sniffing (OLE2/OOXML/ODF/RTF,
  never the extension). Static: oletools inside the VM (VBA source, AutoExec,
  suspicious keywords, IOCs, **VBA stomping via pcodedmp**, XLM), external
  relationships (remote template, Follina `mhtml:`/`ms-msdt`), DDE fields,
  RTF objects (Equation Editor, OLE2Link); embedded OLE objects by class id
  (Equation Editor) and link flag + URL moniker (CVE-2017-0199); RTF parts
  inside .docx (altChunk); self-loading objects in malformed RTF; data hidden
  after an RTF's end; relationships read with an XML parser (any namespace
  prefix); Word field codes assembled across runs (split DDE). Links to free
  hosting / file sharing, bare IPs, program downloads and network shares are
  rated medium (host/src/report.rs link_risk). Render: LibreOffice headless as
  nobody under the monitor with a prebuilt profile; macros never run.
  Spreadsheets are exported by the profile's one macro (`guest/lo-sheets.xba`,
  loading with MacroExecutionMode NEVER_EXECUTE): each sheet is fitted to the
  page width (landscape when wide, never below ~1/3 scale). Known
  LibreOffice start-up probes (paperconf, gpgconf) are denied silently by
  exact match; everything else is reported. Autopsy diffs the profile against
  the pristine template (macro persistence).
- **Regression suite**: `tests/run.sh` (fixtures: `tests/mkpdf.py`,
  `tests/fetch-fixtures.sh`) — expected verdict per sample + selftest.
  Includes Atomic Red Team's Office files (real techniques, harmless
  payloads; pinned commit + SHA-256), which exposed a gap now closed:
  script-host execution (ScriptControl/AddCode/ExecuteStatement/CallByName,
  the MirrorBlast loader) was not treated as code execution. Real samples:
  `tests/malware-run.sh` (password zips, extracted to RAM one at a time).
- **Corpus run** (`tests/fetch-pdfjs-corpus.sh` + `tests/corpus-run.sh`):
  979 pdf.js test PDFs — 0 crashes, 0 errors, 0 MALICIOUS. An earlier
  version of this note said every SUSPICIOUS file had "a feature it really
  has"; that was not checked file by file, and it was wrong: a real tutorial
  PDF was flagged because screenshot pixels spelled "/AA". Since then:
  - PDF features come from the object graph (`guest/pdf_walk.js`: every
    action with its type and trigger, embedded files with their real type,
    XFA/RichMedia/media/encryption), never from a byte search; the byte
    scan is only a fallback for files MuPDF cannot read, and says so.
  - Severity follows what an action does: navigation is not reported,
    "open a website / send data / open another file" by itself is medium,
    "start a program" is high, a Launch of a document is not a program;
    attachments are rated by their first bytes.
  - The fake reader runs scripts like Reader does (one global scope, `this`
    = the document, Acrobat's AF* helpers and ADBE object, realistic form
    fields), so ordinary form logic no longer ends in errors. A script that
    runs on open and did nothing risky there (automatic behaviour only;
    clicks are reported separately) is low, not medium.
  - Every remaining SUSPICIOUS file was reviewed by hand: password
    protected (cannot be checked), deliberately broken, renderer hangs,
    real rich media, one script the emulator cannot run. Rule: a corpus
    result is only called correct after looking at it.
- **M5 — live interactive viewing** — done (`host/src/live.rs`,
  `guest-agent/src/live.rs`). The VM stays up (no NIC) and answers
  Render{page,dpi} / Search{query} / GetText{page} / GetLayout{page}. One
  `mutool -F stext` pass gives page sizes + glyph boxes; search returns
  **only rectangles** (numbers), the host draws highlights. GetLayout returns
  one box per text line (numbers) plus the page text, which the app lays
  over the page image as an invisible, selectable layer (copy is forced to
  plain text). Page text is the single text channel, and the only path
  where one host-side bug (in the system's text shaping, which runs as the
  user) could suffice — so it is narrowed hard on the host (`host/src/text.rs`):
  NFC, then only assigned visible characters (no controls, bidi overrides,
  zero-widths, tags, private use, noncharacters, invisible fillers), at most
  3 combining marks per base and 1000 characters per line. File names get
  the same treatment. **Pixels only** (app toggle or `AIRLOCK_PIXELS_ONLY=1`,
  enforced in Rust) turns the text channel off entirely; search still works.
- **M6 — Tauri desktop app** — `app/`. Webview receives PNGs encoded by Rust
  from validated pixels, numbers and sanitised text (inserted via
  textContent only). Strict CSP, no remote content, capabilities =
  core:default. File dialog and drag-and-drop hand Rust a *path*; the
  webview never reads document bytes. Analyze runs in separate VMs while
  viewing continues.
- **M7 — hardening** — partly done: sinkhole seccomp, hardened guest kernel
  (`guest/build-kernel.sh`, fragment `guest/kernel-hardening.config`),
  VM-death detection, spare-uid VMM (wall 12; replaces the jailer, which
  must be started as root for every VM). Text-channel hardening (wall 13)
  and fuzzing (wall 14; stable-Rust randomised tests, no coverage guidance —
  found and fixed two text-limit bypasses). Web view sandboxed (wall 15). Open: Landlock
  on the app's main process — it runs only our (fuzzed) Rust, and Landlock
  forbids the mounts bwrap needs, so it first needs VM launching split into
  a helper started before the restriction; gVisor inside the guest.
  PERF_EVENTS cannot be disabled on x86; the renderer monitor denies it.
- **Phase 2 — Windows detonation**: QEMU/KVM Windows guest with real Office,
  snapshot revert, sinkhole, time acceleration, out-of-VM introspection

## Layout

- `proto/` — shared wire format (no_std, tested)
- `guest-agent/` — PID 1 in the VM (static musl)
- `guest/build-rootfs.sh` — rootless guest image build
- `host/` — `airlock` CLI
- `vendor/` — Firecracker + guest kernel (downloaded, checksummed; gitignored)
