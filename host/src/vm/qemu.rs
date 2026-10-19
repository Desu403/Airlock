//! Windows: boots one disposable VM with QEMU on the Windows Hypervisor
//! Platform (WHPX). The same kernel (as a bzImage) and image as on Linux.
//!
//! Isolation layers, outermost first:
//!  * a Job object per VM: QEMU cannot start any other program, is killed
//!    with airlock (kill on job close), has a memory ceiling and no access
//!    to the clipboard, desktop or other windows;
//!  * QEMU with only what the VM needs: no network card, no display, no
//!    USB, no shared folders; disks are raw files in a private run dir;
//!  * the hypervisor (WHPX) separates the VM from Windows;
//!  * inside: the same read-only root and monitored renderer as on Linux.
//!
//! The VM's link to airlock is a virtio-serial port connected to an AF_UNIX
//! socket in the run dir (Windows has no vsock).

use super::{ext_hint, Spec};
use anyhow::{bail, Context, Result};
use std::fs;
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

pub struct Assets {
    /// qemu-system-x86_64.exe
    pub vmm: PathBuf,
    pub kernel: PathBuf,
    pub rootfs: PathBuf,
    /// Not used on Windows yet (the analysis VM has no fake internet here).
    pub sinkhole: PathBuf,
}

impl Assets {
    /// `%AIRLOCK_LIB%`, then the folder of the airlock program, then
    /// `%LOCALAPPDATA%\airlock` (where the installer puts the viewer).
    pub fn locate() -> Result<Self> {
        let exe_dir = std::env::current_exe()?.parent().map(Path::to_path_buf).unwrap_or_default();
        let at = |lib: PathBuf| Assets {
            vmm: lib.join("qemu").join("qemu-system-x86_64.exe"),
            kernel: lib.join("bzImage"),
            rootfs: lib.join("rootfs.ext4"),
            sinkhole: lib.join("sinkhole.exe"),
        };
        let mut candidates = Vec::new();
        if let Some(lib) = std::env::var_os("AIRLOCK_LIB") {
            candidates.push(at(PathBuf::from(lib)));
        } else {
            candidates.push(at(exe_dir));
            if let Some(local) = std::env::var_os("LOCALAPPDATA") {
                candidates.push(at(PathBuf::from(local).join("airlock")));
            }
        }
        let n = candidates.len();
        for (i, a) in candidates.into_iter().enumerate() {
            let complete = [&a.vmm, &a.kernel, &a.rootfs].iter().all(|p| p.exists());
            if complete || i + 1 == n {
                for p in [&a.vmm, &a.kernel, &a.rootfs] {
                    if !p.exists() {
                        bail!("missing {} (reinstall airlock)", p.display());
                    }
                }
                return Ok(a);
            }
        }
        unreachable!()
    }
}

/// No spare-uid isolation on Windows (the Job object takes its place).
pub fn uid_shift() -> bool {
    false
}

pub struct RunDir {
    pub path: PathBuf,
}

impl RunDir {
    /// A fresh folder in the user's own temp dir (private to the user).
    pub fn create(tag: &str) -> Result<Self> {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos();
        let root = std::env::temp_dir().join("airlock");
        fs::create_dir_all(&root)?;
        sweep_stale(&root);
        let path = root.join(format!("{}-{nanos}-{tag}", std::process::id()));
        fs::create_dir(&path)?;
        Ok(RunDir { path })
    }
    pub fn link_path(&self) -> PathBuf {
        self.path.join("link.sock")
    }
    /// Listens where QEMU's virtio-serial port connects.
    pub fn listen(&self) -> Result<crate::link::Listener> {
        let l = crate::link::Listener::bind(self.link_path()).context("creating the VM's link socket")?;
        l.set_nonblocking(true)?;
        Ok(l)
    }
}

impl Drop for RunDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Removes run dirs left by airlock processes that are gone (they hold a
/// copy of the document).
fn sweep_stale(dir: &Path) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let Some(pid) = name.split('-').next().and_then(|p| p.parse::<u32>().ok()) else { continue };
        if !process_alive(pid) {
            let _ = fs::remove_dir_all(e.path());
        }
    }
}

fn process_alive(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, STILL_ACTIVE};
    use windows_sys::Win32::System::Threading::{GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return false;
        }
        let mut code = 0u32;
        let ok = GetExitCodeProcess(h, &mut code) != 0 && code == STILL_ACTIVE as u32;
        CloseHandle(h);
        ok
    }
}

/// An empty ext4 scratch disk: a copy of the blank one made at build time
/// (scripts/windows.sh; Windows has no mke2fs). No guest data involved.
pub fn make_scratch_disk(dir: &Path) -> Result<PathBuf> {
    let template = Assets::locate()?.rootfs.with_file_name("scratch.img");
    let p = dir.join("scratch.img");
    fs::copy(&template, &p).with_context(|| format!("copying {}", template.display()))?;
    Ok(p)
}

/// Kernel options QEMU's VM adds to the shared ones: the virtio-serial link,
/// and no wipe of all memory at boot (init_on_free: about 9 s on WHPX, where
/// each first touch of a page is slow). Memory is still cleared when handed
/// out (init_on_alloc stays on), and it all dies with the VM.
const WINDOWS_ARGS: &str = "airlock.link=serial init_on_free=0";

pub fn spawn(assets: &Assets, run: &RunDir, spec: &Spec, log: &Path) -> Result<Child> {
    let mut boot_args = format!("console=ttyS0 reboot=k panic=-1 pci=off ro root=/dev/vda quiet init=/sbin/airlock-agent ipv6.disable=1 airlock.mode={} {WINDOWS_ARGS}", spec.mode);
    // Test hooks, as on Linux: the guest's PID 1 dies mid-session; the
    // viewing VM turns hostile (`airlock containment`).
    if std::env::var_os("AIRLOCK_CRASHTEST").is_some() && spec.mode != "autopsy" {
        boot_args.push_str(" airlock.crashtest");
    }
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
    if let Some(n) = spec.entry.filter(|n| *n < 100_000) {
        boot_args.push_str(&format!(" airlock.entry={n}"));
    }
    if let Some(e) = spec.ext.as_deref().filter(|e| ext_hint(&format!(".{e}")).as_deref() == Some(*e)) {
        boot_args.push_str(" airlock.ext=");
        boot_args.push_str(e);
    }
    let path = |p: &Path| p.to_str().map(str::to_owned).context("non-unicode path");
    // QEMU's option syntax: a comma inside a value is written twice.
    let opt = |p: &Path| path(p).map(|s| s.replace(',', ",,"));
    // WHPX by default; AIRLOCK_QEMU_ACCEL=tcg (software, slow) for test
    // machines without the hypervisor.
    let accel = match std::env::var("AIRLOCK_QEMU_ACCEL").as_deref() {
        Ok("tcg") => "tcg",
        _ => "whpx",
    };
    let mut cmd = Command::new(&assets.vmm);
    cmd.args(["-M", "microvm,acpi=on", "-accel", accel, "-m", "2048", "-smp", "2"])
        .args(["-no-user-config", "-display", "none", "-monitor", "none", "-parallel", "none", "-nic", "none", "-no-reboot"])
        .arg("-kernel").arg(&assets.kernel)
        .arg("-append").arg(&boot_args)
        .arg("-serial").arg(format!("file:{}", path(log)?));
    let mut drives = vec![("rootfs", assets.rootfs.clone(), true)];
    drives.extend(spec.drives.iter().map(|d| (d.id, d.path.clone(), d.read_only)));
    for (id, p, ro) in &drives {
        cmd.arg("-drive").arg(format!("id={id},file={},format=raw,if=none,readonly={},cache=none", opt(p)?, if *ro { "on" } else { "off" }));
        cmd.arg("-device").arg(format!("virtio-blk-device,drive={id}"));
    }
    cmd.args(["-device", "virtio-serial-device"])
        .arg("-chardev").arg(format!("socket,id=link,path={}", opt(&run.link_path())?))
        .args(["-device", "virtserialport,chardev=link,name=airlock"]);
    let log_file = fs::File::options().append(true).create(true).open(run.path.join("qemu.log"))?;
    cmd.stdin(Stdio::null()).stdout(log_file.try_clone()?).stderr(log_file);
    // Started suspended, put in its job, then let go: it never runs outside it.
    const CREATE_SUSPENDED: u32 = 0x0000_0004;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const BELOW_NORMAL_PRIORITY_CLASS: u32 = 0x0000_4000;
    cmd.creation_flags(CREATE_SUSPENDED | CREATE_NO_WINDOW | BELOW_NORMAL_PRIORITY_CLASS);
    let mut child = cmd.spawn().context("starting QEMU")?;
    if let Err(e) = jail(&child) {
        let _ = child.kill();
        return Err(e);
    }
    Ok(child)
}

/// Puts the (suspended) QEMU process in a new Job object and resumes it.
fn jail(child: &Child) -> Result<()> {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32};
    use windows_sys::Win32::System::JobObjects::*;
    use windows_sys::Win32::System::Threading::{OpenThread, ResumeThread, THREAD_SUSPEND_RESUME};
    unsafe {
        let job: HANDLE = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        if job.is_null() {
            bail!("creating the VM's job: {}", std::io::Error::last_os_error());
        }
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | JOB_OBJECT_LIMIT_JOB_MEMORY
            | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
        limits.BasicLimitInformation.ActiveProcessLimit = 1;
        // The VM's 2 GB plus QEMU itself.
        limits.JobMemoryLimit = 3 << 30;
        let ui = JOBOBJECT_BASIC_UI_RESTRICTIONS {
            UIRestrictionsClass: JOB_OBJECT_UILIMIT_DESKTOP
                | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
                | JOB_OBJECT_UILIMIT_EXITWINDOWS
                | JOB_OBJECT_UILIMIT_GLOBALATOMS
                | JOB_OBJECT_UILIMIT_HANDLES
                | JOB_OBJECT_UILIMIT_READCLIPBOARD
                | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
                | JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
        };
        let set = SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits as *const _ as *const _, std::mem::size_of_val(&limits) as u32) != 0
            && SetInformationJobObject(job, JobObjectBasicUIRestrictions, &ui as *const _ as *const _, std::mem::size_of_val(&ui) as u32) != 0
            && AssignProcessToJobObject(job, child.as_raw_handle() as HANDLE) != 0;
        if !set {
            let e = std::io::Error::last_os_error();
            CloseHandle(job);
            bail!("putting QEMU in its job: {e}");
        }
        // Kept open for as long as airlock runs: closing it kills the VM.
        keep_job(job as isize);
        // Resume QEMU's (only) thread.
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if snap == INVALID_HANDLE_VALUE {
            bail!("listing QEMU's threads: {}", std::io::Error::last_os_error());
        }
        let mut te: THREADENTRY32 = std::mem::zeroed();
        te.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
        let mut resumed = false;
        let mut more = Thread32First(snap, &mut te) != 0;
        while more {
            if te.th32OwnerProcessID == child.id() {
                let t = OpenThread(THREAD_SUSPEND_RESUME, 0, te.th32ThreadID);
                if !t.is_null() {
                    resumed |= ResumeThread(t) != u32::MAX;
                    CloseHandle(t);
                }
            }
            more = Thread32Next(snap, &mut te) != 0;
        }
        CloseHandle(snap);
        if !resumed {
            bail!("could not start QEMU's thread");
        }
    }
    Ok(())
}

/// Job handles of running VMs; those whose VM has ended are closed.
fn keep_job(job: isize) {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::JobObjects::{JobObjectBasicAccountingInformation, QueryInformationJobObject, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION};
    static JOBS: std::sync::Mutex<Vec<isize>> = std::sync::Mutex::new(Vec::new());
    let mut jobs = JOBS.lock().unwrap_or_else(|e| e.into_inner());
    jobs.retain(|&j| unsafe {
        let mut info: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = std::mem::zeroed();
        let ok = QueryInformationJobObject(j as _, JobObjectBasicAccountingInformation, &mut info as *mut _ as *mut _, std::mem::size_of_val(&info) as u32, std::ptr::null_mut()) != 0;
        if ok && info.ActiveProcesses == 0 {
            CloseHandle(j as _);
            false
        } else {
            true
        }
    });
    jobs.push(job);
}
