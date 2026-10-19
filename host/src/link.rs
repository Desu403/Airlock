//! The host end of the VM connection, a stream socket in the VM's private
//! run dir: on Linux the Unix socket Firecracker relays vsock to, on Windows
//! an AF_UNIX socket (Windows 10 1803+) that QEMU's virtio-serial port
//! connects to. Same API either way.

#[cfg(unix)]
pub use std::os::unix::net::{UnixListener as Listener, UnixStream as Stream};
#[cfg(windows)]
pub use uds_windows::{UnixListener as Listener, UnixStream as Stream};
