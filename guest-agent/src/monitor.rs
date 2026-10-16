//! Runs untrusted code (the renderer, or the selftest payload) under a
//! seccomp filter whose interesting syscalls are delegated to this process
//! (SECCOMP_RET_USER_NOTIF). We decide per call: allow, deny, or kill — and
//! record what was attempted, with arguments read from the child's memory.
//!
//! Honest limit: if the guest *kernel* gets exploited, these events can be
//! suppressed or forged. That is why the host also watches from outside
//! (network sinkhole, autopsy VM) — signals the guest cannot touch.

use airlock_proto::Ind;
use std::io::Read;
use std::os::fd::RawFd;
use std::os::unix::fs::FileExt;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const RENDER_UID: u32 = 65534;
pub const RENDER_GID: u32 = 65534;
const MAX_EVENTS: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Net {
    /// No sockets at all (view mode).
    Deny,
    /// IPv4/IPv6 sockets allowed (they can only reach the sinkhole) and logged.
    AllowInet,
}

pub struct Opts<'a> {
    pub net: Net,
    pub timeout: Duration,
    /// RLIMIT_AS; None for programs that reserve huge address ranges.
    pub mem_limit: Option<u64>,
    pub env: &'a [(&'a str, &'a str)],
    /// Local AF_UNIX sockets (LibreOffice IPC): allowed and not reported.
    /// They can only reach processes inside this VM.
    pub allow_unix: bool,
    /// Let the program fork (LibreOffice helpers). Children inherit the
    /// filter, so anything they try to execute is still denied and logged.
    pub allow_fork: bool,
    /// Exec attempts that are known-benign for this program: still denied,
    /// but not reported. Exact "path [argv]" match; a trailing '*' = prefix.
    pub quiet_exec: &'a [&'a str],
}

impl Opts<'static> {
    pub fn new(net: Net, timeout: Duration) -> Self {
        Opts { net, timeout, mem_limit: Some(1536 << 20), env: &[], allow_unix: false, allow_fork: false, quiet_exec: &[] }
    }
}

pub struct Outcome {
    pub stdout: Option<Vec<u8>>,
    pub events: Vec<(Ind, String)>,
}

// --- seccomp plumbing -------------------------------------------------------

const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
const SECCOMP_SET_MODE_FILTER: libc::c_ulong = 1;
const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_ulong = 1 << 3;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;
const NOTIF_RECV: libc::c_ulong = 0xC050_2100;
const NOTIF_SEND: libc::c_ulong = 0xC018_2101;
const NOTIF_ID_VALID: libc::c_ulong = 0x4008_2102;

#[repr(C)]
#[derive(Default)]
struct SeccompData {
    nr: i32,
    arch: u32,
    ip: u64,
    args: [u64; 6],
}

#[repr(C)]
#[derive(Default)]
struct Notif {
    id: u64,
    pid: u32,
    flags: u32,
    data: SeccompData,
}

#[repr(C)]
#[derive(Default)]
struct NotifResp {
    id: u64,
    val: i64,
    error: i32,
    flags: u32,
}

/// Syscalls handed to the supervisor. Everything else is allowed natively.
const WATCHED: &[i64] = &[
    libc::SYS_execve,
    libc::SYS_execveat,
    libc::SYS_fork,
    libc::SYS_vfork,
    libc::SYS_clone,
    libc::SYS_clone3,
    libc::SYS_socket,
    libc::SYS_socketpair,
    libc::SYS_connect,
    libc::SYS_sendto,
    libc::SYS_sendmsg,
    libc::SYS_ptrace,
    libc::SYS_process_vm_readv,
    libc::SYS_process_vm_writev,
    // Kernel attack surface: nothing a document renderer needs.
    libc::SYS_mount,
    libc::SYS_umount2,
    libc::SYS_pivot_root,
    libc::SYS_unshare,
    libc::SYS_setns,
    libc::SYS_bpf,
    libc::SYS_keyctl,
    libc::SYS_add_key,
    libc::SYS_request_key,
    libc::SYS_init_module,
    libc::SYS_finit_module,
    libc::SYS_delete_module,
    libc::SYS_kexec_load,
    libc::SYS_perf_event_open,
    libc::SYS_userfaultfd,
    libc::SYS_io_uring_setup,
    libc::SYS_iopl,
    libc::SYS_ioperm,
    libc::SYS_setuid,
    libc::SYS_setgid,
    libc::SYS_setreuid,
    libc::SYS_setresuid,
    libc::SYS_chroot,
    libc::SYS_personality,
    libc::SYS_open_by_handle_at,
];

fn kernel_surface_name(nr: i64) -> Option<&'static str> {
    Some(match nr {
        libc::SYS_mount => "mount",
        libc::SYS_umount2 => "umount2",
        libc::SYS_pivot_root => "pivot_root",
        libc::SYS_unshare => "unshare",
        libc::SYS_setns => "setns",
        libc::SYS_bpf => "bpf",
        libc::SYS_keyctl => "keyctl",
        libc::SYS_add_key => "add_key",
        libc::SYS_request_key => "request_key",
        libc::SYS_init_module => "init_module",
        libc::SYS_finit_module => "finit_module",
        libc::SYS_delete_module => "delete_module",
        libc::SYS_kexec_load => "kexec_load",
        libc::SYS_perf_event_open => "perf_event_open",
        libc::SYS_userfaultfd => "userfaultfd",
        libc::SYS_io_uring_setup => "io_uring_setup",
        libc::SYS_iopl => "iopl",
        libc::SYS_ioperm => "ioperm",
        libc::SYS_setuid => "setuid",
        libc::SYS_setgid => "setgid",
        libc::SYS_setreuid => "setreuid",
        libc::SYS_setresuid => "setresuid",
        libc::SYS_chroot => "chroot",
        libc::SYS_personality => "personality",
        libc::SYS_open_by_handle_at => "open_by_handle_at",
        _ => return None,
    })
}

fn build_filter() -> Vec<libc::sock_filter> {
    let stmt = |code: u16, k: u32| libc::sock_filter { code, jt: 0, jf: 0, k };
    let jeq = |k: u32, jt: u8, jf: u8| libc::sock_filter { code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16, jt, jf, k };
    let ld = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
    let ret = (libc::BPF_RET | libc::BPF_K) as u16;
    let mut f = vec![
        stmt(ld, 4), // seccomp_data.arch
        jeq(AUDIT_ARCH_X86_64, 1, 0),
        stmt(ret, SECCOMP_RET_KILL_PROCESS),
        stmt(ld, 0), // seccomp_data.nr
        // x32 ABI syscalls are a classic filter bypass: kill.
        libc::sock_filter { code: (libc::BPF_JMP | libc::BPF_JGE | libc::BPF_K) as u16, jt: 0, jf: 1, k: 0x4000_0000 },
        stmt(ret, SECCOMP_RET_KILL_PROCESS),
    ];
    let n = WATCHED.len();
    for (i, &nr) in WATCHED.iter().enumerate() {
        // match -> jump to the NOTIF return placed after the list
        f.push(jeq(nr as u32, (n - i) as u8, 0));
    }
    f.push(stmt(ret, SECCOMP_RET_ALLOW));
    f.push(stmt(ret, SECCOMP_RET_USER_NOTIF));
    f
}

// --- reading the child's memory ----------------------------------------------

fn read_mem(pid: u32, addr: u64, len: usize) -> Option<Vec<u8>> {
    if addr == 0 || len == 0 {
        return None;
    }
    let f = std::fs::File::open(format!("/proc/{pid}/mem")).ok()?;
    let mut buf = vec![0u8; len];
    let n = f.read_at(&mut buf, addr).ok()?;
    buf.truncate(n);
    Some(buf)
}

fn read_cstr(pid: u32, addr: u64) -> String {
    match read_mem(pid, addr, 200) {
        Some(b) => {
            let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
            String::from_utf8_lossy(&b[..end]).into_owned()
        }
        None => "?".into(),
    }
}

fn read_argv(pid: u32, addr: u64) -> String {
    let Some(ptrs) = read_mem(pid, addr, 8 * 6) else { return String::new() };
    let mut parts = Vec::new();
    for p in ptrs.chunks_exact(8) {
        let a = u64::from_le_bytes(p.try_into().unwrap());
        if a == 0 {
            break;
        }
        parts.push(read_cstr(pid, a));
    }
    parts.join(" ")
}

fn read_sockaddr(pid: u32, addr: u64, len: u64) -> Option<String> {
    let b = read_mem(pid, addr, len.min(128) as usize)?;
    if b.len() < 2 {
        return None;
    }
    let family = u16::from_le_bytes([b[0], b[1]]) as i32;
    match family {
        libc::AF_INET if b.len() >= 8 => {
            let port = u16::from_be_bytes([b[2], b[3]]);
            Some(format!("{}.{}.{}.{}:{port}", b[4], b[5], b[6], b[7]))
        }
        libc::AF_INET6 if b.len() >= 24 => {
            let port = u16::from_be_bytes([b[2], b[3]]);
            let ip = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&b[8..24]).ok()?);
            Some(format!("[{ip}]:{port}"))
        }
        libc::AF_UNIX => Some(format!("unix:{}", String::from_utf8_lossy(&b[2..]).trim_end_matches('\0'))),
        libc::AF_VSOCK => Some("vsock".into()),
        f => Some(format!("family {f}")),
    }
}

/// Loopback traffic never leaves the VM (e.g. LibreOffice probing CUPS on :631).
fn is_loopback(dst: &str) -> bool {
    dst.starts_with("127.") || dst.starts_with("[::1]")
}

fn family_name(f: i32) -> String {
    match f {
        libc::AF_INET => "AF_INET".into(),
        libc::AF_INET6 => "AF_INET6".into(),
        libc::AF_UNIX => "AF_UNIX".into(),
        libc::AF_NETLINK => "AF_NETLINK".into(),
        libc::AF_PACKET => "AF_PACKET".into(),
        libc::AF_VSOCK => "AF_VSOCK".into(),
        libc::AF_ALG => "AF_ALG".into(),
        other => format!("family {other}"),
    }
}

// --- the supervisor -------------------------------------------------------------

enum Verdict {
    Allow,
    Deny(i32),
    Kill,
}

struct Supervisor {
    quiet_exec: Vec<String>,
    root_pid: u32,
    first_exec_done: bool,
    net: Net,
    allow_unix: bool,
    allow_fork: bool,
    events: Arc<Mutex<Vec<(Ind, String)>>>,
}

impl Supervisor {
    fn record(&self, ind: Ind, text: String) -> bool {
        let mut ev = self.events.lock().unwrap();
        if !ev.iter().any(|(i, t)| *i == ind && *t == text) {
            ev.push((ind, text));
        }
        ev.len() < MAX_EVENTS
    }

    fn decide(&mut self, n: &Notif) -> Verdict {
        let a = n.data.args;
        let nr = n.data.nr as i64;
        let pid = n.pid;
        let keep_going = match nr {
            libc::SYS_execve if !self.first_exec_done && pid == self.root_pid => {
                self.first_exec_done = true;
                return Verdict::Allow;
            }
            libc::SYS_execve | libc::SYS_execveat => {
                let (path, argv) = if nr == libc::SYS_execve {
                    (read_cstr(pid, a[0]), read_argv(pid, a[1]))
                } else {
                    (read_cstr(pid, a[1]), read_argv(pid, a[2]))
                };
                let what = format!("{path} [{argv}]");
                let expected = self.quiet_exec.iter().any(|q| match q.strip_suffix('*') {
                    Some(prefix) => what.starts_with(prefix),
                    None => what == *q,
                });
                let ok = expected || self.record(Ind::Exec, what);
                return if ok { Verdict::Deny(libc::EPERM) } else { Verdict::Kill };
            }
            libc::SYS_clone if a[0] & libc::CLONE_THREAD as u64 != 0 => return Verdict::Allow,
            libc::SYS_clone3 => {
                // struct clone_args starts with u64 flags.
                let flags = read_mem(pid, a[0], 8).map(|b| u64::from_le_bytes(b[..8].try_into().unwrap_or([0; 8]))).unwrap_or(0);
                if flags & libc::CLONE_THREAD as u64 != 0 {
                    return Verdict::Deny(libc::ENOSYS); // libc falls back to clone()
                }
                let ok = self.record(Ind::ProcessCreate, "clone3 (new process)".into());
                return if ok { Verdict::Deny(libc::EAGAIN) } else { Verdict::Kill };
            }
            libc::SYS_fork | libc::SYS_vfork | libc::SYS_clone if self.allow_fork => return Verdict::Allow,
            libc::SYS_fork | libc::SYS_vfork | libc::SYS_clone => {
                let ok = self.record(Ind::ProcessCreate, "fork/clone (new process)".into());
                return if ok { Verdict::Deny(libc::EAGAIN) } else { Verdict::Kill };
            }
            libc::SYS_socket | libc::SYS_socketpair if self.allow_unix && a[0] as i32 == libc::AF_UNIX => return Verdict::Allow,
            libc::SYS_connect if self.allow_unix && read_sockaddr(pid, a[1], a[2]).is_some_and(|d| d.starts_with("unix:")) => {
                return Verdict::Allow
            }
            libc::SYS_socket | libc::SYS_socketpair => {
                let fam = a[0] as i32;
                let kind = match (a[1] as i32) & 0xf {
                    libc::SOCK_STREAM => "stream",
                    libc::SOCK_DGRAM => "dgram",
                    libc::SOCK_RAW => "raw",
                    _ => "other",
                };
                let inet = fam == libc::AF_INET || fam == libc::AF_INET6;
                let ok = if inet {
                    true // reported at connect()/sendto(), where the destination is known
                } else {
                    self.record(Ind::KernelSurface, format!("socket({}, {kind})", family_name(fam)))
                };
                if !ok {
                    return Verdict::Kill;
                }
                return if inet && self.net == Net::AllowInet { Verdict::Allow } else { Verdict::Deny(libc::EACCES) };
            }
            libc::SYS_connect => {
                let dst = read_sockaddr(pid, a[1], a[2]).unwrap_or_else(|| "?".into());
                is_loopback(&dst) || self.record(Ind::Connect, format!("connect {dst}"))
            }
            libc::SYS_sendto => match read_sockaddr(pid, a[4], a[5]) {
                Some(dst) if is_loopback(&dst) => true,
                Some(dst) => self.record(Ind::Connect, format!("sendto {dst}")),
                None => true, // connected socket: already logged at connect()
            },
            libc::SYS_sendmsg => true,
            libc::SYS_ptrace | libc::SYS_process_vm_readv | libc::SYS_process_vm_writev => {
                let what = match nr {
                    libc::SYS_ptrace => format!("ptrace(request {}, pid {})", a[0] as i64, a[1] as i64),
                    _ => format!("cross-process memory access (pid {})", a[0] as i64),
                };
                let ok = self.record(Ind::Ptrace, what);
                return if ok { Verdict::Deny(libc::EPERM) } else { Verdict::Kill };
            }
            _ => {
                let name = kernel_surface_name(nr).unwrap_or("unknown");
                let ok = self.record(Ind::KernelSurface, format!("{name}()"));
                return if ok { Verdict::Deny(libc::EPERM) } else { Verdict::Kill };
            }
        };
        if keep_going {
            Verdict::Allow
        } else {
            Verdict::Kill
        }
    }

    fn serve(mut self, fd: RawFd, stop: Arc<AtomicBool>) {
        loop {
            let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
            let r = unsafe { libc::poll(&mut pfd, 1, 100) };
            if r < 0 || pfd.revents & (libc::POLLHUP | libc::POLLERR) != 0 {
                break;
            }
            if r == 0 {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                continue;
            }
            let mut n = Notif::default();
            if unsafe { libc::ioctl(fd, NOTIF_RECV as _, &mut n) } != 0 {
                continue;
            }
            let verdict = self.decide(&n);
            let mut id = n.id;
            if unsafe { libc::ioctl(fd, NOTIF_ID_VALID as _, &mut id) } != 0 {
                continue; // the calling thread is already gone
            }
            let mut resp = NotifResp { id: n.id, ..Default::default() };
            match verdict {
                Verdict::Allow => resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE,
                Verdict::Deny(e) => resp.error = -e,
                Verdict::Kill => {
                    self.record(Ind::RendererAbnormal, "killed: too many suspicious actions".into());
                    unsafe { libc::kill(-(self.root_pid as i32), libc::SIGKILL) };
                    unsafe { libc::kill(self.root_pid as i32, libc::SIGKILL) };
                    resp.error = -libc::EPERM;
                }
            }
            unsafe { libc::ioctl(fd, NOTIF_SEND as _, &mut resp) };
        }
        unsafe { libc::close(fd) };
    }
}

/// Runs `argv` as nobody under the monitor. `cwd` must be writable by nobody.
pub fn run(argv: &[&str], cwd: &str, opts: &Opts) -> Outcome {
    let (net, timeout, mem_limit, allow_unix, allow_fork) = (opts.net, opts.timeout, opts.mem_limit, opts.allow_unix, opts.allow_fork);
    let quiet_exec: Vec<String> = opts.quiet_exec.iter().map(|s| s.to_string()).collect();
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut pipe = [0 as RawFd; 2];
    if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Outcome { stdout: None, events: vec![(Ind::RendererAbnormal, "monitor: pipe failed".into())] };
    }
    let (rd, wr) = (pipe[0], pipe[1]);

    let stop = Arc::new(AtomicBool::new(false));
    let sup_events = events.clone();
    let sup_stop = stop.clone();
    let supervisor = std::thread::spawn(move || {
        // The child reports (pid, listener fd) right before its exec, which
        // then blocks until we answer — so we must fetch the fd first.
        let mut msg = [0u8; 8];
        let mut f = unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(rd) };
        if f.read_exact(&mut msg).is_err() {
            return;
        }
        let pid = u32::from_le_bytes(msg[..4].try_into().unwrap());
        let child_fd = i32::from_le_bytes(msg[4..].try_into().unwrap());
        let fd = unsafe {
            let pidfd = libc::syscall(libc::SYS_pidfd_open, pid, 0) as i32;
            let fd = if pidfd >= 0 { libc::syscall(libc::SYS_pidfd_getfd, pidfd, child_fd, 0) as i32 } else { -1 };
            if pidfd >= 0 {
                libc::close(pidfd);
            }
            fd
        };
        if fd < 0 {
            // Without the listener the child would block forever in execve.
            unsafe { libc::kill(pid as i32, libc::SIGKILL) };
            sup_events.lock().unwrap().push((Ind::RendererAbnormal, "monitor: could not attach".into()));
            return;
        }
        Supervisor { quiet_exec, root_pid: pid, first_exec_done: false, net, allow_unix, allow_fork, events: sup_events }.serve(fd, sup_stop);
    });

    let filter = build_filter();
    let mut cmd = Command::new(argv[0]);
    cmd.args(&argv[1..])
        .current_dir(cwd)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .envs(opts.env.iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .uid(RENDER_UID)
        .gid(RENDER_GID)
        .process_group(0);
    unsafe {
        cmd.pre_exec(move || {
            libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            let lim = |res, v: u64| {
                let r = libc::rlimit { rlim_cur: v, rlim_max: v };
                libc::setrlimit(res, &r);
            };
            lim(libc::RLIMIT_CORE, 0);
            lim(libc::RLIMIT_FSIZE, 128 * 1024 * 1024);
            if let Some(m) = mem_limit {
                lim(libc::RLIMIT_AS, m); // heap sprays fail here, not in the VM's OOM killer
            }
            let prog = libc::sock_fprog { len: filter.len() as u16, filter: filter.as_ptr() as *mut _ };
            let fd = libc::syscall(libc::SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let mut msg = [0u8; 8];
            msg[..4].copy_from_slice(&(libc::getpid() as u32).to_le_bytes());
            msg[4..].copy_from_slice(&(fd as i32).to_le_bytes());
            libc::write(wr, msg.as_ptr() as *const _, 8);
            Ok(())
        });
    }
    let spawned = cmd.spawn();
    unsafe { libc::close(wr) };
    let mut child = match spawned {
        Ok(c) => c,
        Err(e) => {
            stop.store(true, Ordering::Relaxed);
            let _ = supervisor.join();
            let mut ev = std::mem::take(&mut *events.lock().unwrap());
            ev.push((Ind::RendererAbnormal, format!("could not start {}: {e}", argv[0])));
            return Outcome { stdout: None, events: ev };
        }
    };

    let mut stdout = child.stdout.take().unwrap();
    let reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf);
        buf
    });
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break Some(st),
            Ok(None) if start.elapsed() > timeout => {
                unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(_) => break None,
        }
    };
    stop.store(true, Ordering::Relaxed);
    let _ = supervisor.join();
    let out = reader.join().ok();
    let mut ev = std::mem::take(&mut *events.lock().unwrap());
    let stdout = match status {
        Some(st) if st.success() => out,
        Some(st) => {
            use std::os::unix::process::ExitStatusExt;
            if let Some(sig) = st.signal() {
                ev.push((Ind::RendererAbnormal, format!("{} crashed (signal {sig})", argv[0])));
            }
            None
        }
        None => {
            ev.push((Ind::RendererAbnormal, format!("{} timed out after {}s", argv[0], timeout.as_secs())));
            None
        }
    };
    Outcome { stdout, events: ev }
}
