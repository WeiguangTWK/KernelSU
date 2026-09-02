#![allow(clippy::unreadable_literal)]
use anyhow::bail;

use crate::ksu_uapi;
use std::fs;
use std::os::fd::RawFd;
use std::sync::OnceLock;

// Global driver fd cache
static DRIVER_FD: OnceLock<RawFd> = OnceLock::new();
static INFO_CACHE: OnceLock<ksu_uapi::ksu_get_info_cmd> = OnceLock::new();

fn scan_driver_fd() -> Option<RawFd> {
    let fd_dir = fs::read_dir("/proc/self/fd").ok()?;

    for entry in fd_dir.flatten() {
        if let Ok(fd_num) = entry.file_name().to_string_lossy().parse::<i32>() {
            let link_path = format!("/proc/self/fd/{fd_num}");
            if let Ok(target) = fs::read_link(&link_path) {
                let target_str = target.to_string_lossy();
                if target_str.contains("[ksu_driver]") {
                    return Some(fd_num);
                }
            }
        }
    }

    None
}

// Get cached driver fd
fn init_driver_fd() -> Option<RawFd> {
    let fd = scan_driver_fd();
    if fd.is_none() {
        let mut fd = -1;
        unsafe {
            libc::syscall(
                libc::SYS_reboot,
                ksu_uapi::KSU_INSTALL_MAGIC1,
                ksu_uapi::KSU_INSTALL_MAGIC2,
                0,
                &mut fd,
            );
        };
        if fd >= 0 { Some(fd) } else { None }
    } else {
        fd
    }
}

fn driver_fd() -> std::io::Result<RawFd> {
    if let Some(fd) = DRIVER_FD.get() {
        return Ok(*fd);
    }
    let fd = init_driver_fd().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "KernelSU driver file descriptor is unavailable",
        )
    })?;
    match DRIVER_FD.set(fd) {
        Ok(()) => Ok(fd),
        Err(extra_fd) => {
            // Another thread initialized the shared descriptor first.
            unsafe { libc::close(extra_fd) };
            Ok(*DRIVER_FD
                .get()
                .expect("KernelSU driver fd initialized concurrently"))
        }
    }
}

pub fn provenance_probe_fd() -> std::io::Result<RawFd> {
    driver_fd()
}

// ioctl wrapper using libc
fn ksuctl<T>(request: u32, arg: *mut T) -> std::io::Result<i32> {
    use std::io;

    let fd = driver_fd()?;
    unsafe {
        let ret = libc::ioctl(fd as libc::c_int, request as i32, arg);
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(ret)
        }
    }
}

fn ksuctl_fd<T>(fd: RawFd, request: u32, arg: *mut T) -> std::io::Result<i32> {
    use std::io;

    unsafe {
        let ret = libc::ioctl(fd as libc::c_int, request as i32, arg);
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(ret)
        }
    }
}

// API implementations
pub fn get_info() -> ksu_uapi::ksu_get_info_cmd {
    *INFO_CACHE.get_or_init(|| {
        let mut cmd = ksu_uapi::ksu_get_info_cmd {
            version: 0,
            flags: 0,
            features: 0,
            uapi_version: 0,
        };
        if ksuctl(ksu_uapi::KSU_IOCTL_GET_INFO, &raw mut cmd).is_err() {
            let _ = ksuctl(ksu_uapi::KSU_IOCTL_GET_INFO_LEGACY, &raw mut cmd);
        }
        cmd
    })
}

pub fn get_version() -> i32 {
    get_info().version as i32
}

pub fn is_late_load() -> bool {
    get_info().flags & ksu_uapi::KSU_GET_INFO_FLAG_LATE_LOAD != 0
}

pub fn is_lkm() -> bool {
    get_info().flags & ksu_uapi::KSU_GET_INFO_FLAG_LKM != 0
}

pub const fn uapi_version() -> u32 {
    ksu_uapi::KERNEL_SU_UAPI_VERSION
}

pub fn runtime_mode() -> &'static str {
    if is_late_load() {
        "late-load"
    } else if is_lkm() {
        "lkm"
    } else {
        "built-in"
    }
}

pub fn ensure_uapi_version_matched() -> anyhow::Result<()> {
    let kernel_uapi = get_info().uapi_version;
    let userspace_uapi = uapi_version();
    if kernel_uapi != userspace_uapi {
        bail!(
            "UAPI version mismatch: kernel={kernel_uapi}, ksud={userspace_uapi}. Please update KernelSU!"
        );
    }
    Ok(())
}

pub fn grant_root() -> std::io::Result<()> {
    ksuctl(ksu_uapi::KSU_IOCTL_GRANT_ROOT, std::ptr::null_mut::<u8>())?;
    Ok(())
}

fn report_event(event: u32) -> std::io::Result<()> {
    let mut cmd = ksu_uapi::ksu_report_event_cmd { event };
    ksuctl(ksu_uapi::KSU_IOCTL_REPORT_EVENT, &raw mut cmd)?;
    Ok(())
}

pub fn report_post_fs_data() {
    let _ = report_event(ksu_uapi::EVENT_POST_FS_DATA);
}

pub fn report_post_fs_data_checked() -> std::io::Result<()> {
    report_event(ksu_uapi::EVENT_POST_FS_DATA)
}

pub fn report_boot_complete() {
    let _ = report_event(ksu_uapi::EVENT_BOOT_COMPLETED);
}

pub fn report_module_mounted() {
    let _ = report_event(ksu_uapi::EVENT_MODULE_MOUNTED);
}

pub fn try_check_kernel_safemode() -> std::io::Result<bool> {
    let mut cmd = ksu_uapi::ksu_check_safemode_cmd { in_safe_mode: 0 };
    ksuctl(ksu_uapi::KSU_IOCTL_CHECK_SAFEMODE, &raw mut cmd)?;
    Ok(cmd.in_safe_mode != 0)
}

pub fn get_provenance_info() -> std::io::Result<ksu_uapi::ksu_provenance_info_v1> {
    let mut info = unsafe { std::mem::zeroed::<ksu_uapi::ksu_provenance_info_v1>() };
    ksuctl(ksu_uapi::KSU_IOCTL_PROVENANCE_GET_INFO, &raw mut info)?;
    if usize::from(info.size) != std::mem::size_of_val(&info)
        || info.version != ksu_uapi::KSU_PROVENANCE_UAPI_VERSION
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid audit provenance diagnostics response",
        ));
    }
    Ok(info)
}

pub fn get_provenance_eligibility_info()
-> std::io::Result<ksu_uapi::ksu_provenance_eligibility_info_v1> {
    let mut info = unsafe { std::mem::zeroed::<ksu_uapi::ksu_provenance_eligibility_info_v1>() };
    ksuctl(
        ksu_uapi::KSU_IOCTL_PROVENANCE_GET_ELIGIBILITY,
        &raw mut info,
    )?;
    if usize::from(info.size) != std::mem::size_of_val(&info)
        || info.version != ksu_uapi::KSU_PROVENANCE_UAPI_VERSION
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid audit provenance eligibility response",
        ));
    }
    Ok(info)
}

pub fn get_provenance_context_status() -> std::io::Result<ksu_uapi::ksu_provenance_context_status_v1>
{
    let mut status = unsafe { std::mem::zeroed::<ksu_uapi::ksu_provenance_context_status_v1>() };
    ksuctl(
        ksu_uapi::KSU_IOCTL_PROVENANCE_GET_CONTEXT_STATUS,
        &raw mut status,
    )?;
    if usize::from(status.size) != std::mem::size_of_val(&status)
        || status.version != ksu_uapi::KSU_PROVENANCE_UAPI_VERSION
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid audit provenance context status response",
        ));
    }
    Ok(status)
}

pub fn get_current_provenance_context()
-> std::io::Result<ksu_uapi::ksu_provenance_current_context_v1> {
    let mut current = unsafe { std::mem::zeroed::<ksu_uapi::ksu_provenance_current_context_v1>() };
    ksuctl(
        ksu_uapi::KSU_IOCTL_PROVENANCE_GET_CURRENT_CONTEXT,
        &raw mut current,
    )?;
    if usize::from(current.size) != std::mem::size_of_val(&current)
        || current.version != ksu_uapi::KSU_PROVENANCE_UAPI_VERSION
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid current provenance context response",
        ));
    }
    Ok(current)
}

fn provenance_control_on_fd(
    fd: RawFd,
    command: &mut ksu_uapi::ksu_provenance_control_cmd_v1,
) -> std::io::Result<i32> {
    ksuctl_fd(
        fd,
        ksu_uapi::KSU_IOCTL_PROVENANCE_CONTROL,
        std::ptr::from_mut(command),
    )
}

pub fn claim_provenance_supervisor(
    eligibility_generation: u64,
    boot_claim_nonce: [u8; 16],
) -> std::io::Result<ksu_uapi::ksu_provenance_claim_result_v1> {
    let mut request = ksu_uapi::ksu_provenance_claim_supervisor_v1 {
        size: std::mem::size_of::<ksu_uapi::ksu_provenance_claim_supervisor_v1>() as u16,
        version: ksu_uapi::KSU_PROVENANCE_UAPI_VERSION,
        flags: 0,
        eligibility_generation,
        boot_claim_nonce,
        reserved: [0; 32],
    };
    let mut result = unsafe { std::mem::zeroed::<ksu_uapi::ksu_provenance_claim_result_v1>() };
    result.size = std::mem::size_of_val(&result) as u16;
    result.version = ksu_uapi::KSU_PROVENANCE_UAPI_VERSION;
    result.endpoint_fd = -1;
    let mut command = ksu_uapi::ksu_provenance_control_cmd_v1 {
        size: std::mem::size_of::<ksu_uapi::ksu_provenance_control_cmd_v1>() as u16,
        version: ksu_uapi::KSU_PROVENANCE_UAPI_VERSION,
        operation:
            ksu_uapi::ksu_provenance_control_operation_KSU_PROVENANCE_CONTROL_CLAIM_SUPERVISOR
                as u16,
        flags: 0,
        request_size: std::mem::size_of_val(&request) as u32,
        response_size: std::mem::size_of_val(&result) as u32,
        request: std::ptr::from_mut(&mut request) as u64,
        response: std::ptr::from_mut(&mut result) as u64,
        reserved: [0; 4],
    };
    let fd = driver_fd()?;
    provenance_control_on_fd(fd, &mut command)?;
    if usize::from(result.size) != std::mem::size_of_val(&result)
        || result.version != ksu_uapi::KSU_PROVENANCE_UAPI_VERSION
        || result.result != ksu_uapi::ksu_provenance_claim_result_KSU_PROVENANCE_CLAIM_RESULT_OK
        || result.endpoint_fd < 0
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid successful provenance supervisor claim",
        ));
    }
    Ok(result)
}

pub fn create_provenance_launch(
    supervisor_fd: RawFd,
    descriptor: ksu_uapi::ksu_provenance_context_descriptor_v1,
    timeout_ms: u32,
) -> std::io::Result<ksu_uapi::ksu_provenance_create_launch_result_v1> {
    let mut request = ksu_uapi::ksu_provenance_create_launch_v1 {
        size: std::mem::size_of::<ksu_uapi::ksu_provenance_create_launch_v1>() as u16,
        version: ksu_uapi::KSU_PROVENANCE_UAPI_VERSION,
        flags: 0,
        descriptor,
        timeout_ms,
        reserved0: 0,
        reserved: [0; 16],
    };
    let mut result =
        unsafe { std::mem::zeroed::<ksu_uapi::ksu_provenance_create_launch_result_v1>() };
    let mut command = ksu_uapi::ksu_provenance_control_cmd_v1 {
        size: std::mem::size_of::<ksu_uapi::ksu_provenance_control_cmd_v1>() as u16,
        version: ksu_uapi::KSU_PROVENANCE_UAPI_VERSION,
        operation: ksu_uapi::ksu_provenance_control_operation_KSU_PROVENANCE_CONTROL_CREATE_LAUNCH
            as u16,
        flags: 0,
        request_size: std::mem::size_of_val(&request) as u32,
        response_size: std::mem::size_of_val(&result) as u32,
        request: std::ptr::from_mut(&mut request) as u64,
        response: std::ptr::from_mut(&mut result) as u64,
        reserved: [0; 4],
    };
    provenance_control_on_fd(supervisor_fd, &mut command)?;
    if usize::from(result.size) != std::mem::size_of_val(&result)
        || result.version != ksu_uapi::KSU_PROVENANCE_UAPI_VERSION
        || result.endpoint_fd < 0
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid provenance launch response",
        ));
    }
    Ok(result)
}

pub fn activate_provenance_launch(
    launch_fd: RawFd,
    supervisor_generation: u64,
    context_cookie: u64,
) -> std::io::Result<ksu_uapi::ksu_provenance_activate_result_v1> {
    let mut request = ksu_uapi::ksu_provenance_activate_v1 {
        size: std::mem::size_of::<ksu_uapi::ksu_provenance_activate_v1>() as u16,
        version: ksu_uapi::KSU_PROVENANCE_UAPI_VERSION,
        flags: 0,
        supervisor_generation,
        context_cookie,
        reserved: [0; 8],
    };
    let mut result = unsafe { std::mem::zeroed::<ksu_uapi::ksu_provenance_activate_result_v1>() };
    let mut command = ksu_uapi::ksu_provenance_control_cmd_v1 {
        size: std::mem::size_of::<ksu_uapi::ksu_provenance_control_cmd_v1>() as u16,
        version: ksu_uapi::KSU_PROVENANCE_UAPI_VERSION,
        operation: ksu_uapi::ksu_provenance_control_operation_KSU_PROVENANCE_CONTROL_ACTIVATE
            as u16,
        flags: 0,
        request_size: std::mem::size_of_val(&request) as u32,
        response_size: std::mem::size_of_val(&result) as u32,
        request: std::ptr::from_mut(&mut request) as u64,
        response: std::ptr::from_mut(&mut result) as u64,
        reserved: [0; 4],
    };
    provenance_control_on_fd(launch_fd, &mut command)?;
    if usize::from(result.size) != std::mem::size_of_val(&result)
        || result.version != ksu_uapi::KSU_PROVENANCE_UAPI_VERSION
        || result.context_cookie != context_cookie
        || result.supervisor_generation != supervisor_generation
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid provenance activation response",
        ));
    }
    Ok(result)
}

pub fn close_provenance_context(
    supervisor_fd: RawFd,
    supervisor_generation: u64,
    context_cookie: u64,
) -> std::io::Result<()> {
    let mut request = ksu_uapi::ksu_provenance_close_context_v1 {
        size: std::mem::size_of::<ksu_uapi::ksu_provenance_close_context_v1>() as u16,
        version: ksu_uapi::KSU_PROVENANCE_UAPI_VERSION,
        flags: 0,
        supervisor_generation,
        context_cookie,
        reserved: [0; 8],
    };
    let mut command = ksu_uapi::ksu_provenance_control_cmd_v1 {
        size: std::mem::size_of::<ksu_uapi::ksu_provenance_control_cmd_v1>() as u16,
        version: ksu_uapi::KSU_PROVENANCE_UAPI_VERSION,
        operation: ksu_uapi::ksu_provenance_control_operation_KSU_PROVENANCE_CONTROL_CLOSE_CONTEXT
            as u16,
        flags: 0,
        request_size: std::mem::size_of_val(&request) as u32,
        response_size: 0,
        request: std::ptr::from_mut(&mut request) as u64,
        response: 0,
        reserved: [0; 4],
    };
    provenance_control_on_fd(supervisor_fd, &mut command)?;
    Ok(())
}

pub fn mark_provenance_supervisor_ready(
    supervisor_fd: RawFd,
    supervisor_generation: u64,
) -> std::io::Result<()> {
    let mut request = ksu_uapi::ksu_provenance_supervisor_ready_v1 {
        size: std::mem::size_of::<ksu_uapi::ksu_provenance_supervisor_ready_v1>() as u16,
        version: ksu_uapi::KSU_PROVENANCE_UAPI_VERSION,
        flags: ksu_uapi::KSU_PROVENANCE_READY_IO_URING_TESTED,
        supervisor_generation,
        reserved: [0; 16],
    };
    let mut command = ksu_uapi::ksu_provenance_control_cmd_v1 {
        size: std::mem::size_of::<ksu_uapi::ksu_provenance_control_cmd_v1>() as u16,
        version: ksu_uapi::KSU_PROVENANCE_UAPI_VERSION,
        operation:
            ksu_uapi::ksu_provenance_control_operation_KSU_PROVENANCE_CONTROL_SUPERVISOR_READY
                as u16,
        flags: 0,
        request_size: std::mem::size_of_val(&request) as u32,
        response_size: 0,
        request: std::ptr::from_mut(&mut request) as u64,
        response: 0,
        reserved: [0; 4],
    };
    provenance_control_on_fd(supervisor_fd, &mut command)?;
    Ok(())
}

pub fn expect_provenance_claim_not_ready(
    eligibility_generation: u64,
) -> std::io::Result<ksu_uapi::ksu_provenance_claim_result_v1> {
    let mut request = ksu_uapi::ksu_provenance_claim_supervisor_v1 {
        size: std::mem::size_of::<ksu_uapi::ksu_provenance_claim_supervisor_v1>() as u16,
        version: ksu_uapi::KSU_PROVENANCE_UAPI_VERSION,
        flags: 0,
        eligibility_generation,
        boot_claim_nonce: [0; 16],
        reserved: [0; 32],
    };
    let mut result = unsafe { std::mem::zeroed::<ksu_uapi::ksu_provenance_claim_result_v1>() };
    result.size = std::mem::size_of_val(&result) as u16;
    result.version = ksu_uapi::KSU_PROVENANCE_UAPI_VERSION;
    result.endpoint_fd = -1;
    let mut command = ksu_uapi::ksu_provenance_control_cmd_v1 {
        size: std::mem::size_of::<ksu_uapi::ksu_provenance_control_cmd_v1>() as u16,
        version: ksu_uapi::KSU_PROVENANCE_UAPI_VERSION,
        operation:
            ksu_uapi::ksu_provenance_control_operation_KSU_PROVENANCE_CONTROL_CLAIM_SUPERVISOR
                as u16,
        flags: 0,
        request_size: std::mem::size_of_val(&request) as u32,
        response_size: std::mem::size_of_val(&result) as u32,
        request: std::ptr::from_mut(&mut request) as u64,
        response: std::ptr::from_mut(&mut result) as u64,
        reserved: [0; 4],
    };

    match ksuctl(ksu_uapi::KSU_IOCTL_PROVENANCE_CONTROL, &raw mut command) {
        Err(error) if error.raw_os_error() == Some(libc::EKEYREJECTED) => {}
        Err(error) => return Err(error),
        Ok(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "zero-nonce supervisor claim was unexpectedly accepted",
            ));
        }
    }
    if usize::from(result.size) != std::mem::size_of_val(&result)
        || result.version != ksu_uapi::KSU_PROVENANCE_UAPI_VERSION
        || result.result != ksu_uapi::ksu_provenance_claim_result_KSU_PROVENANCE_CLAIM_WRONG_NONCE
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid zero-nonce supervisor claim rejection",
        ));
    }
    Ok(result)
}

pub fn check_kernel_safemode() -> bool {
    try_check_kernel_safemode().unwrap_or(false)
}

pub fn set_sepolicy(payload: *const u8, payload_len: u64) -> std::io::Result<i32> {
    let mut ioctl_cmd = crate::ksu_uapi::ksu_set_sepolicy_cmd {
        data_len: payload_len,
        data: payload as u64,
    };

    ksuctl(ksu_uapi::KSU_IOCTL_SET_SEPOLICY, &raw mut ioctl_cmd)
}

/// Get feature value and support status from kernel
/// Returns (value, supported)
pub fn get_feature(feature_id: u32) -> std::io::Result<(u64, bool)> {
    let mut cmd = ksu_uapi::ksu_get_feature_cmd {
        feature_id,
        value: 0,
        supported: 0,
    };
    ksuctl(ksu_uapi::KSU_IOCTL_GET_FEATURE, &raw mut cmd)?;
    Ok((cmd.value, cmd.supported != 0))
}

/// Set feature value in kernel
pub fn set_feature(feature_id: u32, value: u64) -> std::io::Result<()> {
    let mut cmd = ksu_uapi::ksu_set_feature_cmd { feature_id, value };
    ksuctl(ksu_uapi::KSU_IOCTL_SET_FEATURE, &raw mut cmd)?;
    Ok(())
}

pub fn get_wrapped_fd(fd: RawFd) -> std::io::Result<RawFd> {
    let mut cmd = ksu_uapi::ksu_get_wrapper_fd_cmd {
        fd: fd as u32,
        flags: 0,
    };
    let result = ksuctl(ksu_uapi::KSU_IOCTL_GET_WRAPPER_FD, &raw mut cmd)?;
    Ok(result)
}

pub fn get_sulog_fd() -> std::io::Result<RawFd> {
    let mut cmd = ksu_uapi::ksu_get_sulog_fd_cmd { flags: 0 };
    let result = ksuctl(ksu_uapi::KSU_IOCTL_GET_SULOG_FD, &raw mut cmd)?;
    Ok(result)
}

/// Get mark status for a process (pid=0 returns total marked count)
pub fn mark_get(pid: i32) -> std::io::Result<u32> {
    let mut cmd = ksu_uapi::ksu_manage_mark_cmd {
        operation: ksu_uapi::KSU_MARK_GET,
        pid,
        result: 0,
    };
    ksuctl(ksu_uapi::KSU_IOCTL_MANAGE_MARK, &raw mut cmd)?;
    Ok(cmd.result)
}

/// Mark a process (pid=0 marks all processes)
pub fn mark_set(pid: i32) -> std::io::Result<()> {
    let mut cmd = ksu_uapi::ksu_manage_mark_cmd {
        operation: ksu_uapi::KSU_MARK_MARK,
        pid,
        result: 0,
    };
    ksuctl(ksu_uapi::KSU_IOCTL_MANAGE_MARK, &raw mut cmd)?;
    Ok(())
}

/// Unmark a process (pid=0 unmarks all processes)
pub fn mark_unset(pid: i32) -> std::io::Result<()> {
    let mut cmd = ksu_uapi::ksu_manage_mark_cmd {
        operation: ksu_uapi::KSU_MARK_UNMARK,
        pid,
        result: 0,
    };
    ksuctl(ksu_uapi::KSU_IOCTL_MANAGE_MARK, &raw mut cmd)?;
    Ok(())
}

/// Refresh mark for all running processes
pub fn mark_refresh() -> std::io::Result<()> {
    let mut cmd = ksu_uapi::ksu_manage_mark_cmd {
        operation: ksu_uapi::KSU_MARK_REFRESH,
        pid: 0,
        result: 0,
    };
    ksuctl(ksu_uapi::KSU_IOCTL_MANAGE_MARK, &raw mut cmd)?;
    Ok(())
}

pub fn nuke_ext4_sysfs(mnt: &str) -> anyhow::Result<()> {
    let c_mnt = std::ffi::CString::new(mnt)?;
    let mut ioctl_cmd = ksu_uapi::ksu_nuke_ext4_sysfs_cmd {
        arg: c_mnt.as_ptr() as u64,
    };
    ksuctl(ksu_uapi::KSU_IOCTL_NUKE_EXT4_SYSFS, &raw mut ioctl_cmd)?;
    Ok(())
}

/// Wipe all entries from umount list
pub fn umount_list_wipe() -> std::io::Result<()> {
    let mut cmd = ksu_uapi::ksu_add_try_umount_cmd {
        arg: 0,
        flags: 0,
        mode: ksu_uapi::KSU_UMOUNT_WIPE,
    };
    ksuctl(ksu_uapi::KSU_IOCTL_ADD_TRY_UMOUNT, &raw mut cmd)?;
    Ok(())
}

/// Add mount point to umount list
pub fn umount_list_add(path: &str, flags: u32) -> anyhow::Result<()> {
    let c_path = std::ffi::CString::new(path)?;
    let mut cmd = ksu_uapi::ksu_add_try_umount_cmd {
        arg: c_path.as_ptr() as u64,
        flags,
        mode: ksu_uapi::KSU_UMOUNT_ADD,
    };
    ksuctl(ksu_uapi::KSU_IOCTL_ADD_TRY_UMOUNT, &raw mut cmd)?;
    Ok(())
}

/// Delete mount point from umount list
pub fn umount_list_del(path: &str) -> anyhow::Result<()> {
    let c_path = std::ffi::CString::new(path)?;
    let mut cmd = ksu_uapi::ksu_add_try_umount_cmd {
        arg: c_path.as_ptr() as u64,
        flags: 0,
        mode: ksu_uapi::KSU_UMOUNT_DEL,
    };
    ksuctl(ksu_uapi::KSU_IOCTL_ADD_TRY_UMOUNT, &raw mut cmd)?;
    Ok(())
}

/// Set current process's process group to init_group (pgid = 0)
pub fn set_init_pgrp() -> std::io::Result<()> {
    ksuctl(
        ksu_uapi::KSU_IOCTL_SET_INIT_PGRP,
        std::ptr::null_mut::<u8>(),
    )?;
    Ok(())
}

pub fn set_ksu_no_new_privs() -> anyhow::Result<()> {
    let result = ksuctl(
        ksu_uapi::KSU_IOCTL_DISABLE_ESCAPE_TO_ROOT,
        std::ptr::null_mut::<u8>(),
    )?;
    if result != 0 {
        bail!("unexpected result: {result}");
    }
    Ok(())
}
