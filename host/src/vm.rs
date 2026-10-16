//! Boots one disposable Firecracker microVM.
//!
//! Isolation layers, outermost first:
//!  * bwrap: fresh user/pid/net/ipc/uts/cgroup namespaces, near-empty FS.
//!    Plain VMs get no capabilities at all. Analysis VMs get a private netns
//!    whose only interfaces are `lo` and `tap0` (wired to the sinkhole);
//!    Firecracker itself is started with every capability dropped.
//!  * Firecracker: minimal Rust VMM with its own seccomp filters.
//!  * Inside: read-only root, monitored renderer as nobody (see guest-agent).

use anyhow::{bail, Context, Result};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

pub struct Assets {
    pub firecracker: PathBuf,
    pub kernel: PathBuf,
    pub rootfs: PathBuf,
    pub sinkhole: PathBuf,
}

impl Assets {
    pub fn locate() -> Result<Self> {
        let base = std::env::var_os("AIRLOCK_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")).join(".."));
        let exe_dir = std::env::current_exe()?.parent().map(Path::to_path_buf).unwrap_or_default();
        let a = Assets {
            firecracker: base.join("vendor/bin/firecracker"),
            // Prefer the hardened kernel (guest/build-kernel.sh); fall back to stock.
            kernel: [base.join("vendor/bin/vmlinux-airlock"), base.join("vendor/bin/vmlinux")]
                .into_iter()
                .find(|p| p.exists())
                .unwrap_or_else(|| base.join("vendor/bin/vmlinux")),
            rootfs: base.join("build/rootfs.ext4"),
            sinkhole: [exe_dir.join("sinkhole"), base.join("host/target/release/sinkhole")]
                .into_iter()
                .find(|p| p.exists())
                .unwrap_or_else(|| exe_dir.join("sinkhole")),
        };
        for p in [&a.firecracker, &a.kernel, &a.rootfs, &a.sinkhole] {
            if !p.exists() {
                bail!("missing {} (run guest/build-rootfs.sh, fetch vendor binaries, cargo build)", p.display());
            }
        }
        Ok(a)
    }
}

pub struct RunDir {
    pub path: PathBuf,
}

impl RunDir {
    pub fn create(tag: &str) -> Result<Self> {
        let base = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos();
        sweep_stale(&base.join("airlock"));
        let path = base.join("airlock").join(format!("{}-{nanos}-{tag}", std::process::id()));
        fs::create_dir_all(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        Ok(RunDir { path })
    }
    pub fn vsock(&self) -> PathBuf {
        self.path.join("v.sock")
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
}

const SANDBOX_PATH: &str = "/usr/bin";

pub fn spawn(assets: &Assets, run: &RunDir, spec: &Spec, log: &Path) -> Result<Child> {
    let mut boot_args = format!("console=ttyS0 reboot=k panic=-1 pci=off ro quiet init=/sbin/airlock-agent ipv6.disable=1 airlock.mode={}", spec.mode);
    // Test hook: the guest's PID 1 dies mid-session -> real kernel panic.
    if std::env::var_os("AIRLOCK_CRASHTEST").is_some() && spec.mode != "autopsy" {
        boot_args.push_str(" airlock.crashtest");
    }
    let mut net_ifaces = vec![];
    if spec.sinkhole_events.is_some() {
        boot_args.push_str(" ip=10.0.0.2::10.0.0.1:255.255.255.0::eth0:off");
        net_ifaces.push(serde_json::json!({ "iface_id": "eth0", "host_dev_name": "tap0", "guest_mac": "06:00:0a:00:00:02" }));
    }
    let mut drives = vec![serde_json::json!({ "drive_id": "rootfs", "path_on_host": "/vm/rootfs.ext4", "is_root_device": true, "is_read_only": true })];
    for d in &spec.drives {
        drives.push(serde_json::json!({ "drive_id": d.id, "path_on_host": format!("/vm/{}.img", d.id), "is_root_device": false, "is_read_only": d.read_only }));
    }
    let cfg = serde_json::json!({
        "boot-source": { "kernel_image_path": "/vm/vmlinux", "boot_args": boot_args },
        "drives": drives,
        "machine-config": { "vcpu_count": 2, "mem_size_mib": 2048, "smt": false },
        "vsock": { "guest_cid": 3, "uds_path": run.vsock() },
        "network-interfaces": net_ifaces
    });
    let cfg_path = run.path.join("vm.json");
    fs::write(&cfg_path, serde_json::to_vec_pretty(&cfg)?)?;

    let log_file = fs::File::create(log)?;
    let run_s = run.path.to_str().context("non-utf8 run dir")?;
    let mut cmd = Command::new("bwrap");
    cmd.args(["--unshare-all", "--die-with-parent", "--new-session", "--clearenv", "--setenv", "PATH", SANDBOX_PATH])
        .args(["--dev", "/dev", "--dev-bind", "/dev/kvm", "/dev/kvm", "--proc", "/proc", "--tmpfs", "/tmp"])
        .arg("--ro-bind").arg(&assets.firecracker).arg("/vm/firecracker")
        .arg("--ro-bind").arg(&assets.kernel).arg("/vm/vmlinux")
        .arg("--ro-bind").arg(&assets.rootfs).arg("/vm/rootfs.ext4")
        .arg("--ro-bind").arg(&cfg_path).arg("/vm/vm.json");
    for d in &spec.drives {
        cmd.arg(if d.read_only { "--ro-bind" } else { "--bind" }).arg(&d.path).arg(format!("/vm/{}.img", d.id));
    }
    // The vsock socket must live at the same path inside and outside.
    cmd.args(["--bind", run_s, run_s]);
    let fc = "/vm/firecracker --no-api --config-file /vm/vm.json --level Warning";

    match &spec.sinkhole_events {
        None => {
            cmd.args(["--cap-drop", "ALL", "--", "/vm/firecracker", "--no-api", "--config-file", "/vm/vm.json", "--level", "Warning"]);
        }
        Some(events) => {
            // Network jail: root *inside a fresh user namespace* (no host
            // privilege), with just enough capability to build tap0 + nft.
            let events = events.to_str().context("non-utf8 path")?;
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
{trace}/vm/sinkhole '{events}' '{ready}' &
i=0; while [ ! -e '{ready}' ]; do i=$((i+1)); [ $i -lt 200 ] || exit 3; sleep 0.02; done
exec setpriv --bounding-set=-all --inh-caps=-all --no-new-privs -- {fc}
"#
            );
            cmd.args(["--uid", "0", "--gid", "0"])
                .args(["--cap-drop", "ALL", "--cap-add", "CAP_NET_ADMIN", "--cap-add", "CAP_NET_RAW", "--cap-add", "CAP_NET_BIND_SERVICE", "--cap-add", "CAP_SETPCAP"])
                .args(if trace_dir.is_some() { &["--cap-add", "CAP_SYS_PTRACE"][..] } else { &[][..] })
                .args(["--dev-bind", "/dev/net/tun", "/dev/net/tun"])
                .args(["--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin", "--symlink", "usr/bin", "/sbin"])
                .args(["--symlink", "usr/lib", "/lib", "--symlink", "usr/lib", "/lib64"])
                .arg("--ro-bind").arg(&assets.sinkhole).arg("/vm/sinkhole")
                .args(["--", "/bin/sh", "-c", &script]);
        }
    }
    cmd.stdin(Stdio::null()).stdout(log_file.try_clone()?).stderr(log_file);
    cmd.spawn().context("starting bwrap/firecracker")
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
