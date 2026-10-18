//! Boots one disposable Firecracker microVM.
//!
//! Isolation layers, outermost first:
//!  * spare uid: Firecracker runs as one of the user's subordinate uids
//!    (/etc/subuid, mapped by newuidmap as in rootless Podman), so an escape
//!    lands in an account that owns nothing — the rootless equivalent of
//!    Firecracker's jailer. Falls back to the user's uid where unavailable.
//!  * bwrap: fresh user/pid/net/ipc/uts/cgroup namespaces, near-empty FS
//!    built only from file descriptors we opened, no further user namespaces.
//!    Plain VMs get no capabilities at all. Analysis VMs get a private netns
//!    whose only interfaces are `lo` and `tap0` (wired to the sinkhole);
//!    Firecracker itself is started with every capability dropped.
//!  * Firecracker: minimal Rust VMM with its own seccomp filters.
//!  * Inside: read-only root, monitored renderer as nobody (see guest-agent).

use anyhow::{bail, Context, Result};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::UnixListener;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;

/// Spare-uid isolation, when this machine supports it: the user has a
/// /etc/subuid + /etc/subgid range that newuidmap accepts (`unshare
/// --map-auto` maps it from inner uid 0), the devices Firecracker opens are
/// usable by any uid (systemd's default 0666), and the run-dir filesystem
/// takes POSIX ACLs.
struct Shift {
    /// Host uid of inner uid 0.
    start: u32,
    /// Usable inner uids: 1..count.
    count: u32,
    /// Holds the run dirs: 0711, so a VM's spare uid can reach its own run
    /// dir by name (granted by ACL) but nobody can list or enter the others.
    base: PathBuf,
}

fn shift() -> Option<&'static Shift> {
    static S: OnceLock<Option<Shift>> = OnceLock::new();
    S.get_or_init(detect_shift).as_ref()
}

pub fn uid_shift() -> bool {
    shift().is_some()
}

fn detect_shift() -> Option<Shift> {
    let world_rw = |p: &str| fs::metadata(p).is_ok_and(|m| m.permissions().mode() & 0o006 == 0o006);
    if std::env::var_os("AIRLOCK_NO_UIDSHIFT").is_some() || !world_rw("/dev/kvm") || !world_rw("/dev/net/tun") {
        return None;
    }
    let uid = unsafe { libc::getuid() };
    let name = user_name(uid)?;
    // `--map-auto` uses the first range listed for the user.
    let range = |file: &str| {
        fs::read_to_string(file).ok()?.lines().find_map(|l| {
            let mut f = l.split(':');
            let who = f.next()?;
            let (start, count) = (f.next()?.parse::<u32>().ok()?, f.next()?.parse::<u32>().ok()?);
            (who == name || who == uid.to_string()).then_some((start, count))
        })
    };
    let (start, ucount) = range("/etc/subuid")?;
    let (_, gcount) = range("/etc/subgid")?;
    let count = ucount.min(gcount).min(65536);
    if count < 2 {
        return None;
    }
    let mapped = Command::new("unshare")
        .args(["--map-auto", "--setuid", "1", "--setgid", "1", "true"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    if !mapped {
        return None;
    }
    let base = std::env::temp_dir().join(format!("airlock-{uid}"));
    private_dir(&base, 0o711).ok()?;
    let probe = base.join(format!("probe-{}", std::process::id()));
    let _ = fs::create_dir(&probe);
    let acl = grant(&probe, start + 1).is_ok();
    let _ = fs::remove_dir(&probe);
    acl.then_some(Shift { start, count, base })
}

fn user_name(uid: u32) -> Option<String> {
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 16384];
    let mut res = std::ptr::null_mut();
    let r = unsafe { libc::getpwuid_r(uid, &mut pw, buf.as_mut_ptr(), buf.len(), &mut res) };
    if r != 0 || res.is_null() {
        return None;
    }
    Some(unsafe { std::ffi::CStr::from_ptr(pw.pw_name) }.to_string_lossy().into_owned())
}

/// Creates (or reuses) a directory that must be ours and not a symlink —
/// the shift base lives in the shared temp dir.
fn private_dir(p: &Path, mode: u32) -> Result<()> {
    match fs::create_dir(p) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    let m = fs::symlink_metadata(p)?;
    if !m.is_dir() || m.uid() != unsafe { libc::getuid() } {
        bail!("{} is not a directory owned by you", p.display());
    }
    fs::set_permissions(p, fs::Permissions::from_mode(mode))?;
    Ok(())
}

/// Sets the ACL of `dir` to: owner rwx, host uid `uid` rwx, nobody else.
fn grant(dir: &Path, uid: u32) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    const UNDEFINED: u32 = u32::MAX;
    // Linux xattr ACL format: version, then (tag, perm, id) sorted by tag:
    // USER_OBJ, USER, GROUP_OBJ, MASK, OTHER.
    let mut acl = 2u32.to_le_bytes().to_vec();
    for (tag, perm, id) in [(0x01u16, 7u16, UNDEFINED), (0x02, 7, uid), (0x04, 0, UNDEFINED), (0x10, 7, UNDEFINED), (0x20, 0, UNDEFINED)] {
        acl.extend(tag.to_le_bytes());
        acl.extend(perm.to_le_bytes());
        acl.extend(id.to_le_bytes());
    }
    let path = std::ffi::CString::new(dir.as_os_str().as_bytes())?;
    let r = unsafe { libc::setxattr(path.as_ptr(), c"system.posix_acl_access".as_ptr(), acl.as_ptr().cast(), acl.len(), 0) };
    if r == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

pub struct Assets {
    pub firecracker: PathBuf,
    pub kernel: PathBuf,
    pub rootfs: PathBuf,
    pub sinkhole: PathBuf,
}

impl Assets {
    /// Finds the VM assets: `$AIRLOCK_HOME` (a source tree), then an
    /// installed layout next to the binary (`<prefix>/bin/airlock` ->
    /// `<prefix>/lib/airlock/`, see scripts/install.sh), then the source tree
    /// this binary was built from.
    pub fn locate() -> Result<Self> {
        let exe_dir = std::env::current_exe()?.parent().map(Path::to_path_buf).unwrap_or_default();
        let source_tree = |base: PathBuf| Assets {
            firecracker: base.join("vendor/bin/firecracker"),
            // Prefer the hardened kernel (guest/build-kernel.sh); fall back to stock.
            kernel: [base.join("vendor/bin/vmlinux-airlock"), base.join("vendor/bin/vmlinux")]
                .into_iter()
                .find(|p| p.exists())
                .unwrap_or_else(|| base.join("vendor/bin/vmlinux")),
            rootfs: base.join("build/rootfs.ext4"),
            // An update kit (<lib>/kit) first uses the installed one next to
            // it: an AppImage's own copy sits in a FUSE mount that the VM's
            // spare uid cannot read.
            sinkhole: [base.join("../sinkhole"), exe_dir.join("sinkhole"), exe_dir.join("../lib/airlock/sinkhole"), base.join("host/target/release/sinkhole")]
                .into_iter()
                .find(|p| p.exists())
                .unwrap_or_else(|| exe_dir.join("sinkhole")),
        };
        let installed = |lib: PathBuf| Assets {
            firecracker: lib.join("firecracker"),
            kernel: lib.join("vmlinux"),
            rootfs: lib.join("rootfs.ext4"),
            sinkhole: lib.join("sinkhole"),
        };
        let candidates = match (std::env::var_os("AIRLOCK_HOME"), std::env::var_os("AIRLOCK_LIB")) {
            (Some(home), _) => vec![source_tree(PathBuf::from(home))],
            // An installed layout chosen explicitly (as scripts/setup.sh's AIRLOCK_LIB).
            (None, Some(lib)) => vec![installed(PathBuf::from(lib))],
            // Next to the binary (scripts/install.sh), then the source tree
            // it was built from (development), then the per-user install
            // the AppImage's setup creates (on other computers the source
            // tree does not exist).
            (None, None) => {
                let mut c = vec![installed(exe_dir.join("../lib/airlock"))];
                // An AppImage uses only what its own setup installed, also on
                // the computer that built it.
                if std::env::var_os("APPIMAGE").is_none() {
                    c.push(source_tree(Path::new(env!("CARGO_MANIFEST_DIR")).join("..")));
                }
                if let Some(home) = std::env::var_os("HOME") {
                    c.push(installed(PathBuf::from(home).join(".local/lib/airlock")));
                }
                c
            }
        };
        let complete = |a: &Assets| [&a.firecracker, &a.kernel, &a.rootfs, &a.sinkhole].iter().all(|p| p.exists());
        let n = candidates.len();
        for (i, a) in candidates.into_iter().enumerate() {
            if complete(&a) || i + 1 == n {
                for p in [&a.firecracker, &a.kernel, &a.rootfs, &a.sinkhole] {
                    if !p.exists() {
                        bail!("missing {} (run scripts/bootstrap.sh, or scripts/install.sh for an installed copy)", p.display());
                    }
                }
                return Ok(a);
            }
        }
        unreachable!()
    }
}

pub struct RunDir {
    pub path: PathBuf,
    /// Inner uid (under `unshare --map-auto`) this VM runs as, if shifted.
    uid: Option<u32>,
}

impl RunDir {
    pub fn create(tag: &str) -> Result<Self> {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos();
        let root = match shift() {
            Some(s) => s.base.clone(),
            None => std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from).unwrap_or_else(std::env::temp_dir).join("airlock"),
        };
        private_dir(&root, if shift().is_some() { 0o711 } else { 0o700 })?;
        sweep_stale(&root);
        let path = root.join(format!("{}-{nanos}-{tag}", std::process::id()));
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        let mut uid = None;
        if shift().is_none() && std::env::var_os("AIRLOCK_NO_UIDSHIFT").is_none() {
            let _ = fs::remove_dir(&path);
            bail!(
                "VMs must run as a separate spare user, not as you, and this computer is not set up for that \
                 (run `airlock doctor` for the one-line fix; AIRLOCK_NO_UIDSHIFT=1 overrides, with less isolation)"
            );
        }
        if let Some(s) = shift() {
            // A different spare uid per VM: concurrent VMs cannot signal or
            // reach each other. Only that uid is granted this directory.
            let inner = 1 + (nanos % (s.count as u128 - 1)) as u32;
            grant(&path, s.start + inner).context("granting the VM's spare uid its run dir")?;
            uid = Some(inner);
        }
        Ok(RunDir { path, uid })
    }
    pub fn vsock(&self) -> PathBuf {
        self.path.join("v.sock")
    }
    /// Listens where the guest's vsock connections arrive (as the spare uid).
    pub fn listen(&self) -> Result<UnixListener> {
        let p = format!("{}_{}", self.vsock().display(), airlock_proto::FRAME_PORT);
        let l = UnixListener::bind(&p)?;
        fs::set_permissions(&p, fs::Permissions::from_mode(0o666))?;
        l.set_nonblocking(true)?;
        Ok(l)
    }
}

/// Removes run dirs left by airlock processes that died without cleaning up
/// (they hold a copy of the document).
fn sweep_stale(dir: &Path) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let Some(pid) = name.split('-').next().and_then(|p| p.parse::<u32>().ok()) else { continue };
        if !Path::new(&format!("/proc/{pid}")).exists() {
            let _ = fs::remove_dir_all(e.path());
        }
    }
}

impl Drop for RunDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Packs the untrusted bytes into a raw disk: header + bytes + padding.
/// The host never interprets the document itself.
pub fn write_doc_disk(dir: &Path, doc: &[u8]) -> Result<PathBuf> {
    let mut img = Vec::with_capacity(doc.len() + 1024);
    img.extend_from_slice(&airlock_proto::DOC_MAGIC);
    img.extend_from_slice(&(doc.len() as u64).to_le_bytes());
    img.extend_from_slice(doc);
    img.resize(img.len().div_ceil(512) * 512, 0);
    let p = dir.join("doc.img");
    fs::write(&p, img)?;
    Ok(p)
}

/// Fresh, empty ext4 scratch disk made by the host (no guest data involved).
pub fn make_scratch_disk(dir: &Path) -> Result<PathBuf> {
    let p = dir.join("scratch.img");
    let st = Command::new("mke2fs")
        .args(["-q", "-t", "ext4", "-O", "^has_journal", "-E", "root_owner=0:0", "-L", "scratch"])
        .arg(&p)
        .arg("96M")
        .status()?;
    if !st.success() {
        bail!("mke2fs failed");
    }
    // Written by the VM's spare uid; the run dir keeps everyone else out.
    fs::set_permissions(&p, fs::Permissions::from_mode(0o666))?;
    Ok(p)
}

pub struct Drive {
    pub id: &'static str,
    pub path: PathBuf,
    pub read_only: bool,
}

pub struct Spec {
    pub mode: &'static str,
    /// Extra drives after the root filesystem (vdb, vdc, ...).
    pub drives: Vec<Drive>,
    /// Wire a NIC to the sinkhole; events are written to this file.
    pub sinkhole_events: Option<PathBuf>,
    /// Extra kernel command line options for the agent (fixed strings only).
    pub options: &'static [&'static str],
    /// The file's extension ("cpp", "jpg"): which language to colour, as the
    /// document disk carries no name. Only [a-z0-9]{1,8} reaches the VM.
    pub ext: Option<String>,
}

/// "Report.CPP" -> Some("cpp"); anything else (no dot, odd characters) -> None.
pub fn ext_hint(name: &str) -> Option<String> {
    let (_, ext) = name.rsplit_once('.')?;
    let ext = ext.to_ascii_lowercase();
    (1..=8).contains(&ext.len()).then_some(()).filter(|_| ext.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())).map(|_| ext)
}

const SANDBOX_PATH: &str = "/usr/bin";

pub fn spawn(assets: &Assets, run: &RunDir, spec: &Spec, log: &Path) -> Result<Child> {
    let mut boot_args = format!("console=ttyS0 reboot=k panic=-1 pci=off ro quiet init=/sbin/airlock-agent ipv6.disable=1 airlock.mode={}", spec.mode);
    // Test hook: the guest's PID 1 dies mid-session -> real kernel panic.
    if std::env::var_os("AIRLOCK_CRASHTEST").is_some() && spec.mode != "autopsy" {
        boot_args.push_str(" airlock.crashtest");
    }
    // Test hook (`airlock containment`): the viewing VM turns hostile.
    if spec.mode == "live" {
        if let Ok(t @ ("attack" | "garbage" | "stress")) = std::env::var("AIRLOCK_GUEST_TEST").as_deref() {
            boot_args.push_str(" airlock.test=");
            boot_args.push_str(t);
        }
    }
    for o in spec.options {
        boot_args.push(' ');
        boot_args.push_str(o);
    }
    if let Some(e) = spec.ext.as_deref().filter(|e| ext_hint(&format!(".{e}")).as_deref() == Some(*e)) {
        boot_args.push_str(" airlock.ext=");
        boot_args.push_str(e);
    }
    let mut net_ifaces = vec![];
    if spec.sinkhole_events.is_some() {
        boot_args.push_str(" ip=10.0.0.2::10.0.0.1:255.255.255.0::eth0:off");
        net_ifaces.push(serde_json::json!({ "iface_id": "eth0", "host_dev_name": "tap0", "guest_mac": "06:00:0a:00:00:02" }));
    }
    // The assets may sit under a private home dir that the spare uid cannot
    // traverse, and bwrap resolves bind sources by path. So they are not
    // mounted at all: they are inherited as descriptors and opened through
    // /proc/self/fd inside, which checks only the files' own permissions.
    let mut fds: Vec<fs::File> = Vec::new();
    let firecracker = pass_fd(&mut fds, &assets.firecracker)?;
    let kernel = pass_fd(&mut fds, &assets.kernel)?;
    let rootfs = pass_fd(&mut fds, &assets.rootfs)?;
    let mut drives = vec![serde_json::json!({ "drive_id": "rootfs", "path_on_host": rootfs, "is_root_device": true, "is_read_only": true })];
    for d in &spec.drives {
        drives.push(serde_json::json!({ "drive_id": d.id, "path_on_host": format!("/vm/{}.img", d.id), "is_root_device": false, "is_read_only": d.read_only }));
    }
    let cfg = serde_json::json!({
        "boot-source": { "kernel_image_path": kernel, "boot_args": boot_args },
        "drives": drives,
        "machine-config": { "vcpu_count": 2, "mem_size_mib": 2048, "smt": false },
        "vsock": { "guest_cid": 3, "uds_path": run.vsock() },
        "network-interfaces": net_ifaces
    });
    let cfg_path = run.path.join("vm.json");
    fs::write(&cfg_path, serde_json::to_vec_pretty(&cfg)?)?;

    let log_file = fs::File::create(log)?;
    let run_s = run.path.to_str().context("non-utf8 run dir")?;
    let mut cmd = if let Some(uid) = run.uid {
        let uid = uid.to_string();
        let mut c = Command::new("unshare");
        // Few processes for the jail (it needs about ten). The count is per
        // user, so it is set once running as the VM's own spare uid.
        c.args(["--map-auto", "--setuid", &uid, "--setgid", &uid, "--", "prlimit", "--nproc=64", "--", "bwrap"]);
        c
    } else {
        Command::new("bwrap")
    };
    cmd.args(["--unshare-all", "--unshare-user", "--die-with-parent", "--new-session", "--clearenv", "--setenv", "PATH", SANDBOX_PATH])
        .args(["--dev", "/dev", "--dev-bind", "/dev/kvm", "/dev/kvm", "--proc", "/proc", "--tmpfs", "/tmp"]);
    // Everything from the host is bound from a descriptor we opened: the
    // spare uid needs no access to the paths (home dirs, $XDG_RUNTIME_DIR).
    bind_fd(&mut cmd, &mut fds, "--ro-bind-fd", &cfg_path, "/vm/vm.json")?;
    for d in &spec.drives {
        bind_fd(&mut cmd, &mut fds, if d.read_only { "--ro-bind-fd" } else { "--bind-fd" }, &d.path, &format!("/vm/{}.img", d.id))?;
    }
    // The vsock socket must live at the same path inside and outside.
    bind_fd(&mut cmd, &mut fds, "--bind-fd", &run.path, run_s)?;
    let fc = format!("{firecracker} --no-api --config-file /vm/vm.json --level Warning");

    match &spec.sinkhole_events {
        None => {
            cmd.args(["--disable-userns", "--cap-drop", "ALL", "--", &firecracker, "--no-api", "--config-file", "/vm/vm.json", "--level", "Warning"]);
        }
        Some(events) => {
            // Network jail: root *inside a fresh user namespace* (no host
            // privilege), with just enough capability to build tap0 + nft.
            let events = events.to_str().context("non-utf8 path")?;
            let sinkhole = pass_fd(&mut fds, &assets.sinkhole)?;
            let ready = format!("{run_s}/sinkhole.ready");
            // Debug aid for maintaining the sinkhole's seccomp allowlist:
            // AIRLOCK_TRACE_SINKHOLE=<dir> records its syscalls with strace.
            let trace_dir = std::env::var("AIRLOCK_TRACE_SINKHOLE").ok();
            let trace = trace_dir.as_deref().map(|d| format!("strace -f -qq -o '{d}/sinkhole.strace' ")).unwrap_or_default();
            if let Some(d) = &trace_dir {
                cmd.args(["--bind", d, d]);
            }
            let script = format!(
                r#"set -eu
# Same effect as bwrap --disable-userns, which cannot be used here: its extra
# namespace layer would not own this network namespace.
echo 0 > /proc/sys/user/max_user_namespaces
ip link set lo up
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6 || true
echo 1 > /proc/sys/net/ipv6/conf/default/disable_ipv6 || true
ip tuntap add tap0 mode tap user 0
ip addr add 10.0.0.1/24 dev tap0
ip link set tap0 up
nft -f - <<'EOF'
table ip airlock {{
  chain pre {{
    type nat hook prerouting priority dstnat; policy accept;
    iifname "tap0" udp dport 53 redirect to :53
    iifname "tap0" meta l4proto tcp redirect to :9999
  }}
}}
EOF
{trace}{sinkhole} '{events}' '{ready}' &
i=0; while [ ! -e '{ready}' ]; do i=$((i+1)); [ $i -lt 200 ] || exit 3; sleep 0.02; done
exec setpriv --bounding-set=-all --inh-caps=-all --no-new-privs -- {fc}
"#
            );
            cmd.args(["--uid", "0", "--gid", "0"])
                .args(["--cap-drop", "ALL", "--cap-add", "CAP_NET_ADMIN", "--cap-add", "CAP_NET_RAW", "--cap-add", "CAP_NET_BIND_SERVICE", "--cap-add", "CAP_SETPCAP", "--cap-add", "CAP_SYS_RESOURCE"])
                .args(if trace_dir.is_some() { &["--cap-add", "CAP_SYS_PTRACE"][..] } else { &[][..] })
                .args(["--dev-bind", "/dev/net/tun", "/dev/net/tun"])
                .args(["--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin", "--symlink", "usr/bin", "/sbin"])
                .args(["--symlink", "usr/lib", "/lib", "--symlink", "usr/lib", "/lib64"])
                ;
            cmd.args(["--", "/bin/sh", "-c", &script]);
        }
    }
    cmd.stdin(Stdio::null()).stdout(log_file.try_clone()?).stderr(log_file);
    let raw: Vec<i32> = fds.iter().map(|f: &fs::File| f.as_raw_fd()).collect();
    // SAFETY: only async-signal-safe calls (fcntl, setrlimit, setpriority)
    // between fork and exec.
    unsafe {
        cmd.pre_exec(move || {
            for &fd in &raw {
                if libc::fcntl(fd, libc::F_SETFD, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            // Limits for everything in the jail (memory and CPUs are fixed by
            // the VM's own size). No core dumps: they would hold guest memory,
            // i.e. the document.
            let limit = |res, n: u64| libc::setrlimit(res, &libc::rlimit { rlim_cur: n, rlim_max: n });
            if limit(libc::RLIMIT_CORE, 0) != 0 || limit(libc::RLIMIT_NOFILE, 1024) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // Lower CPU priority: a busy VM never makes the desktop stutter.
            libc::setpriority(libc::PRIO_PROCESS, 0, 10);
            Ok(())
        });
    }
    let child = spawn_from_keeper(cmd).context("starting bwrap/firecracker")?;
    drop(fds);
    Ok(child)
}

/// bwrap --die-with-parent ties the VM to the *thread* that started it
/// (PR_SET_PDEATHSIG): started from a short-lived worker thread (the app's
/// blocking pool retires idle threads after seconds), the VM was killed
/// mid-viewing. Every VM is therefore started from one thread that lives as
/// long as the process: VMs still die with airlock, never before.
fn spawn_from_keeper(cmd: Command) -> std::io::Result<std::process::Child> {
    use std::sync::{mpsc, Mutex, OnceLock};
    type Job = (Command, mpsc::Sender<std::io::Result<std::process::Child>>);
    static KEEPER: OnceLock<Mutex<mpsc::Sender<Job>>> = OnceLock::new();
    let keeper = KEEPER.get_or_init(|| {
        let (tx, rx) = mpsc::channel::<Job>();
        std::thread::Builder::new()
            .name("airlock-vm-keeper".into())
            .spawn(move || {
                for (mut cmd, reply) in rx {
                    let _ = reply.send(cmd.spawn());
                }
            })
            .expect("starting the VM keeper thread");
        Mutex::new(tx)
    });
    let (reply, result) = mpsc::channel();
    keeper.lock().unwrap().send((cmd, reply)).map_err(|_| std::io::Error::other("VM keeper thread is gone"))?;
    result.recv().map_err(|_| std::io::Error::other("VM keeper thread is gone"))?
}

/// Opens `src` for the sandbox to inherit; returns its path inside.
fn pass_fd(fds: &mut Vec<fs::File>, src: &Path) -> Result<String> {
    let f = fs::File::open(src).with_context(|| format!("opening {}", src.display()))?;
    let path = format!("/proc/self/fd/{}", f.as_raw_fd());
    fds.push(f);
    Ok(path)
}

/// Opens `src` and passes it to bwrap as `flag FD dest`; the descriptor is
/// inherited across exec (see `spawn`).
fn bind_fd(cmd: &mut Command, fds: &mut Vec<fs::File>, flag: &str, src: &Path, dest: &str) -> Result<()> {
    let f = fs::File::open(src).with_context(|| format!("opening {}", src.display()))?;
    cmd.arg(flag).arg(f.as_raw_fd().to_string()).arg(dest);
    fds.push(f);
    Ok(())
}

/// Guest console output is attacker-controlled text: strip anything that
/// could drive a terminal before a human ever sees it.
pub fn sanitized_log(log: &Path) -> String {
    let raw = fs::read(log).unwrap_or_default();
    raw.iter()
        .map(|&b| match b {
            b'\n' => '\n',
            0x20..=0x7e => b as char,
            _ => '?',
        })
        .collect()
}
