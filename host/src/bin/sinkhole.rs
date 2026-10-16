//! Fake internet for one analysis VM. Runs inside the same network-less jail
//! as Firecracker (its own netns contains only `lo` and `tap0`), so even a
//! fully compromised sinkhole has nowhere to send anything.
//!
//! * DNS (udp/53, any destination via nft redirect): every A query answered
//!   with 10.0.0.1 so the next connection lands here and reveals itself.
//! * TCP (any destination/port via nft redirect to :9999): records the
//!   original destination, HTTP request line + Host, or TLS SNI; answers
//!   HTTP with an empty 200 and hangs up on everything else.
//! * Packet log (AF_PACKET on tap0): every new flow, incl. UDP/ICMP/IPv6
//!   that nothing answers.
//!
//! Output is JSON lines; every string is squashed to short printable ASCII.

use std::collections::HashSet;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream, UdpSocket};
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const GW: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const GUEST_MAC: [u8; 6] = [0x06, 0x00, 0x0a, 0x00, 0x00, 0x02];

type Log = Arc<Mutex<std::fs::File>>;

fn clean(s: &[u8], max: usize) -> String {
    s.iter().take(max).map(|&c| if (0x20..=0x7e).contains(&c) { c as char } else { '?' }).collect()
}

fn emit(log: &Log, v: serde_json::Value) {
    let mut f = log.lock().unwrap();
    let _ = writeln!(f, "{v}");
    let _ = f.flush();
}

// ---------------------------------------------------------------- DNS

/// `sock` is bound to port 53 before privileges are dropped.
fn dns(sock: UdpSocket, log: Log) {
    let mut buf = [0u8; 512];
    loop {
        let Ok((n, peer)) = sock.recv_from(&mut buf) else { continue };
        if let Some(r) = dns_answer(&buf[..n], &log) {
            let _ = sock.send_to(&r, peer);
        }
    }
}

fn dns_answer(q: &[u8], log: &Log) -> Option<Vec<u8>> {
    let n = q.len();
    if n < 17 || u16::from_be_bytes([q[4], q[5]]) != 1 {
        return None;
    }
    let (mut i, mut labels) = (12usize, Vec::new());
    while i < n && q[i] != 0 && labels.len() < 32 {
        let l = q[i] as usize;
        if l > 63 || i + 1 + l >= n {
            return None;
        }
        labels.push(clean(&q[i + 1..i + 1 + l], 63));
        i += 1 + l;
    }
    if i + 5 > n || q[i] != 0 {
        return None;
    }
    let qtype = u16::from_be_bytes([q[i + 1], q[i + 2]]);
    let qend = i + 5;
    emit(log, serde_json::json!({"t": "dns", "name": labels.join("."), "qtype": qtype}));
    let mut r = Vec::with_capacity(qend + 16);
    r.extend_from_slice(&q[0..2]);
    r.extend_from_slice(&[0x81, 0x80, 0, 1]);
    r.extend_from_slice(&[0, (qtype == 1) as u8, 0, 0, 0, 0]);
    r.extend_from_slice(&q[12..qend]);
    if qtype == 1 {
        r.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
        r.extend_from_slice(&GW.octets());
    }
    Some(r)
}

// ---------------------------------------------------------------- TCP

fn original_dst(s: &TcpStream) -> Option<String> {
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let r = unsafe { libc::getsockopt(s.as_raw_fd(), libc::SOL_IP, 80 /* SO_ORIGINAL_DST */, &mut addr as *mut _ as *mut _, &mut len) };
    (r == 0).then(|| format!("{}:{}", Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr)), u16::from_be(addr.sin_port)))
}

fn tls_sni(b: &[u8]) -> Option<String> {
    // record(5) handshake(4) version(2) random(32)
    let mut i = 5 + 4 + 2 + 32;
    let sid = *b.get(i)? as usize;
    i += 1 + sid;
    let cs = u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]) as usize;
    i += 2 + cs;
    let cm = *b.get(i)? as usize;
    i += 1 + cm + 2;
    while i + 4 <= b.len() {
        let (ty, len) = (u16::from_be_bytes([b[i], b[i + 1]]), u16::from_be_bytes([b[i + 2], b[i + 3]]) as usize);
        i += 4;
        if ty == 0 {
            let nl = u16::from_be_bytes([*b.get(i + 3)?, *b.get(i + 4)?]) as usize;
            return Some(clean(b.get(i + 5..i + 5 + nl)?, 200));
        }
        i += len;
    }
    None
}

fn tcp_conn(mut s: TcpStream, log: Log) {
    let dst = original_dst(&s).unwrap_or_else(|| "?".into());
    let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
    let mut buf = vec![0u8; 4096];
    let n = s.read(&mut buf).unwrap_or(0);
    let b = &buf[..n];
    let mut ev = serde_json::json!({"t": "tcp", "dst": dst, "bytes": n});
    if b.first() == Some(&0x16) {
        ev["proto"] = "tls".into();
        if let Some(sni) = tls_sni(b) {
            ev["sni"] = sni.into();
        }
    } else if ["GET ", "POST ", "PUT ", "HEAD ", "OPTIONS ", "DELETE ", "PATCH ", "CONNECT "].iter().any(|m| b.starts_with(m.as_bytes())) {
        ev["proto"] = "http".into();
        let text = String::from_utf8_lossy(b);
        let mut lines = text.lines();
        ev["request"] = clean(lines.next().unwrap_or("").as_bytes(), 200).into();
        if let Some(h) = lines.find(|l| l.to_ascii_lowercase().starts_with("host:")) {
            ev["host"] = clean(h[5..].trim().as_bytes(), 200).into();
        }
        let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    } else if n > 0 {
        ev["first_bytes"] = clean(&b[..n.min(48)], 48).into();
    }
    emit(&log, ev);
}

fn tcp(l: TcpListener, log: Log) {
    let active = Arc::new(Mutex::new(0usize));
    for s in l.incoming().flatten() {
        let a = active.clone();
        if *a.lock().unwrap() >= 64 {
            continue; // drop: flood
        }
        *a.lock().unwrap() += 1;
        let log = log.clone();
        std::thread::spawn(move || {
            tcp_conn(s, log);
            *a.lock().unwrap() -= 1;
        });
    }
}

// ---------------------------------------------------------------- packet log

fn packets(fd: i32, log: Log) {
    let mut seen = HashSet::new();
    let mut buf = [0u8; 2048];
    loop {
        let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut _, buf.len(), 0) };
        if n <= 0 {
            continue;
        }
        let p = &buf[..n as usize];
        if p.len() < 14 {
            continue;
        }
        // Only what the guest sends counts (its NIC has a fixed MAC).
        if p[6..12] != GUEST_MAC {
            continue;
        }
        let ethertype = u16::from_be_bytes([p[12], p[13]]);
        let key = match ethertype {
            0x0800 if p.len() >= 34 => {
                let ip = &p[14..];
                let ihl = ((ip[0] & 0xf) as usize) * 4;
                let src = Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]);
                if src == GW {
                    continue; // our own replies
                }
                let dst = Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]);
                let proto = ip[9];
                let port = ip.get(ihl + 2..ihl + 4).map(|b| u16::from_be_bytes([b[0], b[1]])).unwrap_or(0);
                match proto {
                    6 => format!("tcp {dst}:{port}"),
                    17 => format!("udp {dst}:{port}"),
                    1 => format!("icmp {dst}"),
                    other => format!("ip-proto-{other} {dst}"),
                }
            }
            0x86dd => "ipv6".into(),
            0x0806 => continue, // ARP
            other => format!("ethertype {other:#06x}"),
        };
        if seen.len() < 512 && seen.insert(key.clone()) {
            emit(&log, serde_json::json!({"t": "flow", "flow": key}));
        }
    }
}

fn drop_all_caps() {
    #[repr(C)]
    struct Hdr {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let hdr = Hdr { version: 0x2008_0522, pid: 0 };
    let data = [Data { effective: 0, permitted: 0, inheritable: 0 }; 2];
    unsafe {
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        if libc::syscall(libc::SYS_capset, &hdr, data.as_ptr()) != 0 {
            eprintln!("sinkhole: capset failed");
            std::process::exit(1);
        }
    }
}

/// Allowlist derived from tracing the sinkhole under load (see
/// AIRLOCK_TRACE_SINKHOLE in vm.rs). No open/exec/socket/connect/ptrace:
/// everything it needs is already open when this is installed.
fn lock_down() {
    const ALLOW: &[i64] = &[
        libc::SYS_read, libc::SYS_write, libc::SYS_recvfrom, libc::SYS_sendto, libc::SYS_recvmsg,
        libc::SYS_sendmsg, libc::SYS_accept4, libc::SYS_close, libc::SYS_setsockopt, libc::SYS_getsockopt,
        libc::SYS_futex, libc::SYS_mmap, libc::SYS_munmap, libc::SYS_mprotect, libc::SYS_madvise,
        libc::SYS_mremap, libc::SYS_brk, libc::SYS_rt_sigprocmask, libc::SYS_rt_sigaction,
        libc::SYS_sigaltstack, libc::SYS_set_robust_list, libc::SYS_rseq, libc::SYS_gettid,
        libc::SYS_getpid, libc::SYS_sched_getaffinity, libc::SYS_sched_yield, libc::SYS_clone3,
        libc::SYS_exit, libc::SYS_exit_group, libc::SYS_getrandom, libc::SYS_clock_gettime,
        libc::SYS_clock_nanosleep, libc::SYS_nanosleep, libc::SYS_poll, libc::SYS_ppoll,
        libc::SYS_restart_syscall, libc::SYS_tgkill, libc::SYS_rt_sigreturn,
    ];
    let stmt = |code: u32, k: u32| libc::sock_filter { code: code as u16, jt: 0, jf: 0, k };
    let jeq = |k: u32, jt: u8, jf: u8| libc::sock_filter { code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16, jt, jf, k };
    const KILL: u32 = 0x8000_0000; // SECCOMP_RET_KILL_PROCESS
    const ALLOWED: u32 = 0x7fff_0000;
    let ld = libc::BPF_LD | libc::BPF_W | libc::BPF_ABS;
    let ret = libc::BPF_RET | libc::BPF_K;
    let mut f = vec![
        stmt(ld, 4), // arch
        jeq(0xC000_003E, 1, 0),
        stmt(ret, KILL),
        stmt(ld, 0), // nr
        // clone() only for threads: arg0 low 32 bits must contain CLONE_THREAD.
        jeq(libc::SYS_clone as u32, 0, 4),
        stmt(ld, 16), // args[0] low word
        libc::sock_filter { code: (libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K) as u16, jt: 0, jf: 1, k: libc::CLONE_THREAD as u32 },
        stmt(ret, ALLOWED),
        stmt(ret, KILL),
    ];
    let n = ALLOW.len();
    for (i, &nr) in ALLOW.iter().enumerate() {
        f.push(jeq(nr as u32, (n - i) as u8, 0));
    }
    f.push(stmt(ret, KILL));
    f.push(stmt(ret, ALLOWED));
    let prog = libc::sock_fprog { len: f.len() as u16, filter: f.as_ptr() as *mut _ };
    // SECCOMP_SET_MODE_FILTER with TSYNC: applies to every thread.
    let r = unsafe { libc::syscall(libc::SYS_seccomp, 1, 1, &prog) };
    if r != 0 {
        eprintln!("sinkhole: seccomp failed");
        std::process::exit(1);
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let (Some(out), Some(ready)) = (args.next(), args.next()) else {
        eprintln!("usage: sinkhole <events.jsonl> <ready-file>");
        std::process::exit(2);
    };
    let log: Log = Arc::new(Mutex::new(std::fs::File::create(&out).expect("events file")));

    // Open everything that needs privileges first...
    let pfd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, (libc::ETH_P_ALL as u16).to_be() as i32) };
    if pfd >= 0 {
        let ifname = std::ffi::CString::new("tap0").unwrap();
        let idx = unsafe { libc::if_nametoindex(ifname.as_ptr()) };
        let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
        sll.sll_ifindex = idx as i32;
        unsafe { libc::bind(pfd, &sll as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_ll>() as u32) };
    }
    let dns_sock = UdpSocket::bind((GW, 53)).expect("bind dns");
    let tcp_listener = TcpListener::bind(("0.0.0.0", 9999)).expect("bind tcp");
    // ...then give up every capability for good.
    drop_all_caps();

    // Sockets are bound, so the VM can start; nothing new may be opened after this.
    std::fs::write(ready, b"1").expect("ready file");
    lock_down();

    let dns_log = log.clone();
    std::thread::spawn(move || dns(dns_sock, dns_log));
    let tcp_log = log.clone();
    std::thread::spawn(move || tcp(tcp_listener, tcp_log));
    if pfd >= 0 {
        let plog = log.clone();
        std::thread::spawn(move || packets(pfd, plog));
    }
    loop {
        std::thread::park();
    }
}
