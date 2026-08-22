use anyhow::{Context, Result, bail, ensure};
use log::{info, warn};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::mem::size_of;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::thread;
use std::time::Duration;

use crate::{
    defs, global_audit,
    module_audit_log::AuditEventKind,
    module_response::{self, AuditStateAvailability},
    utils,
};

const AUDITD_LOCK_MODE: u32 = 0o600;
const AUDITD_RESTART_DELAY: Duration = Duration::from_secs(3);
const AUDITD_LOCK_WAIT: Duration = Duration::from_secs(1);
const EVENT_BUF_SIZE: usize = 64 * 1024;
const DEBOUNCE_DELAY: Duration = Duration::from_millis(150);
const PERIODIC_VERIFY_INTERVAL: Duration = Duration::from_secs(30);
const SECURITY_EVENT_QUEUE_CAPACITY: usize = 8;
const MAX_INSTALL_SESSION_TIMEOUT: Duration = Duration::from_secs(600);
const INSTALL_SESSION_POLL_INTERVAL: Duration = Duration::from_millis(100);
const INSTALL_SESSION_LOCK_TIMEOUT: Duration = Duration::from_secs(8);

const IN_ATTRIB: u32 = 0x0000_0004;
const IN_CLOSE_WRITE: u32 = 0x0000_0008;
const IN_MOVED_FROM: u32 = 0x0000_0040;
const IN_MOVED_TO: u32 = 0x0000_0080;
const IN_CREATE: u32 = 0x0000_0100;
const IN_DELETE: u32 = 0x0000_0200;
const IN_DELETE_SELF: u32 = 0x0000_0400;
const IN_MOVE_SELF: u32 = 0x0000_0800;
const IN_UNMOUNT: u32 = 0x0000_2000;
const IN_Q_OVERFLOW: u32 = 0x0000_4000;
const IN_IGNORED: u32 = 0x0000_8000;
const IN_ISDIR: u32 = 0x4000_0000;

const WATCH_MASK: u32 = IN_ATTRIB
    | IN_CLOSE_WRITE
    | IN_MOVED_FROM
    | IN_MOVED_TO
    | IN_CREATE
    | IN_DELETE
    | IN_DELETE_SELF
    | IN_MOVE_SELF
    | IN_UNMOUNT;

struct AuditdLockGuard {
    _lock_file: File,
}

struct AuditdResumeGuard {
    services: Vec<&'static str>,
}

pub struct AuditdShutdownGuard {
    _auditd_lock: AuditdLockGuard,
    _coordinator: AuditCoordinatorGuard,
}

pub struct AuditCoordinatorGuard {
    _lock_file: File,
}

struct AuditdServiceStopOutcome {
    services: Vec<(&'static str, String)>,
    active: Vec<&'static str>,
    failures: Vec<String>,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct InotifyEvent {
    wd: i32,
    mask: u32,
    cookie: u32,
    len: u32,
}

struct InotifyWatcher {
    fd: RawFd,
    watches: BTreeMap<PathBuf, i32>,
    needs_refresh: bool,
}

#[derive(Debug)]
struct SecurityEvent {
    kind: String,
    message: String,
}

static SECURITY_EVENT_SENDER: OnceLock<Option<SyncSender<SecurityEvent>>> = OnceLock::new();

impl AuditdLockGuard {
    fn acquire() -> Result<Option<Self>> {
        utils::ensure_dir_exists(defs::WORKING_DIR)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(AUDITD_LOCK_MODE)
            .open(defs::AUDITD_LOCK_PATH)
            .with_context(|| format!("failed to open {}", defs::AUDITD_LOCK_PATH))?;

        if try_lock_file(&file)? {
            Ok(Some(Self { _lock_file: file }))
        } else {
            Ok(None)
        }
    }
}

impl Drop for AuditdResumeGuard {
    fn drop(&mut self) {
        for service in &self.services {
            match Command::new("start").arg(service).status() {
                Ok(status) if status.success() => {}
                Ok(status) => warn!("failed to restart auditd service {service}: {status}"),
                Err(error) => warn!("failed to restart auditd service {service}: {error:#}"),
            }
        }
    }
}

impl AuditCoordinatorGuard {
    pub fn acquire_blocking() -> Result<Self> {
        utils::ensure_dir_exists(defs::WORKING_DIR)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(AUDITD_LOCK_MODE)
            .open(defs::AUDIT_COORD_LOCK_PATH)
            .with_context(|| format!("failed to open {}", defs::AUDIT_COORD_LOCK_PATH))?;
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        ensure!(
            result == 0,
            "lock audit coordinator: {}",
            io::Error::last_os_error()
        );
        Ok(Self { _lock_file: file })
    }

    fn try_acquire() -> Result<Option<Self>> {
        utils::ensure_dir_exists(defs::WORKING_DIR)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(AUDITD_LOCK_MODE)
            .open(defs::AUDIT_COORD_LOCK_PATH)
            .with_context(|| format!("failed to open {}", defs::AUDIT_COORD_LOCK_PATH))?;
        if try_lock_file(&file)? {
            Ok(Some(Self { _lock_file: file }))
        } else {
            Ok(None)
        }
    }
}

impl InotifyWatcher {
    fn new() -> Result<Self> {
        let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
        if fd < 0 {
            bail!("inotify_init1 failed: {}", io::Error::last_os_error());
        }
        Ok(Self {
            fd,
            watches: BTreeMap::new(),
            needs_refresh: false,
        })
    }

    fn refresh(&mut self) {
        self.clear_watches();
        self.add_dir(Path::new(defs::ADB_DIR));
        self.add_tree(Path::new(defs::MODULE_AUDIT_DIR));
        self.add_tree(Path::new(defs::MODULE_DIR));
        self.add_tree(Path::new(defs::MODULE_UPDATE_DIR));
        self.needs_refresh = false;
    }

    fn clear_watches(&mut self) {
        for watch in self.watches.values() {
            let watch = u32::try_from(*watch).unwrap_or(u32::MAX);
            unsafe {
                libc::inotify_rm_watch(self.fd, watch);
            }
        }
        self.watches.clear();
    }

    fn add_dir(&mut self, path: &Path) {
        if !path.is_dir() || self.watches.contains_key(path) {
            return;
        }

        let Some(path_bytes) = CString::new(path.as_os_str().as_bytes()).ok() else {
            warn!("cannot encode inotify watch path: {}", path.display());
            return;
        };
        let watch = unsafe { libc::inotify_add_watch(self.fd, path_bytes.as_ptr(), WATCH_MASK) };
        if watch < 0 {
            warn!(
                "failed to add inotify watch for {}: {}",
                path.display(),
                io::Error::last_os_error()
            );
            return;
        }
        self.watches.insert(path.to_path_buf(), watch);
    }

    fn add_tree(&mut self, root: &Path) {
        if !root.is_dir() {
            return;
        }

        self.add_dir(root);
        let mut pending = vec![root.to_path_buf()];
        while let Some(directory) = pending.pop() {
            let Ok(entries) = std::fs::read_dir(&directory) else {
                continue;
            };
            for entry in entries.flatten() {
                if entry.file_type().is_ok_and(|file_type| file_type.is_dir()) {
                    pending.push(entry.path());
                }
            }
        }
    }

    fn drain_events(&mut self) -> Result<bool> {
        let mut observed = false;
        let mut buffer = vec![0_u8; EVENT_BUF_SIZE];

        loop {
            let read = unsafe {
                libc::read(
                    self.fd,
                    buffer.as_mut_ptr().cast::<libc::c_void>(),
                    buffer.len(),
                )
            };
            if read < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::WouldBlock {
                    return Ok(observed);
                }
                return Err(error).context("read inotify events");
            }
            if read == 0 {
                return Ok(observed);
            }

            observed = true;
            let read_len = usize::try_from(read).context("inotify read length overflow")?;
            self.process_bytes(&buffer[..read_len]);
        }
    }

    fn process_bytes(&mut self, bytes: &[u8]) {
        let event_size = size_of::<InotifyEvent>();
        let mut offset = 0_usize;

        while offset.saturating_add(event_size) <= bytes.len() {
            let event = unsafe {
                std::ptr::read_unaligned(bytes[offset..].as_ptr().cast::<InotifyEvent>())
            };
            let name_len = usize::try_from(event.len).unwrap_or(usize::MAX);
            let Some(total_len) = event_size.checked_add(name_len) else {
                break;
            };
            if offset.saturating_add(total_len) > bytes.len() {
                break;
            }

            let name_start = offset.saturating_add(event_size);
            let name_bytes = &bytes[name_start..name_start.saturating_add(name_len)];
            self.handle_event(event, name_bytes);
            offset = offset.saturating_add(total_len);
        }
    }

    fn handle_event(&mut self, event: InotifyEvent, name_bytes: &[u8]) {
        if event.mask & IN_IGNORED != 0 {
            self.watches.retain(|_, watch| *watch != event.wd);
        }

        if event.mask & IN_Q_OVERFLOW != 0 {
            self.needs_refresh = true;
            if let Err(error) = global_audit::record_event(AuditEventKind::WatchOverflow) {
                warn!("failed to record audit watch overflow event: {error:#}");
            }
            notify_security_event("watch_overflow", "审计监听队列溢出，可能出现审计疏漏");
        }

        if event.mask & (IN_DELETE_SELF | IN_MOVE_SELF | IN_UNMOUNT) != 0 {
            self.needs_refresh = true;
        }

        if event.mask & (IN_CREATE | IN_MOVED_TO) != 0
            && event.mask & IN_ISDIR != 0
            && let Some(parent) = self.path_for_watch(event.wd)
        {
            let name = event_name(name_bytes);
            self.add_dir(&parent.join(name));
        }
    }

    fn path_for_watch(&self, watch_descriptor: i32) -> Option<PathBuf> {
        self.watches
            .iter()
            .find_map(|(path, watch)| (*watch == watch_descriptor).then(|| path.clone()))
    }
}

fn try_lock_file(file: &File) -> Result<bool> {
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result == 0 {
        return Ok(true);
    }

    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::WouldBlock {
        return Ok(false);
    }
    if let Some(code) = error.raw_os_error()
        && (code == libc::EWOULDBLOCK || code == libc::EAGAIN)
    {
        return Ok(false);
    }

    Err(error.into())
}

fn event_name(name_bytes: &[u8]) -> String {
    let length = name_bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(name_bytes.len());
    String::from_utf8_lossy(&name_bytes[..length]).into_owned()
}

fn verify_and_respond(last_contained: &mut BTreeSet<String>, store_missing_recorded: &mut bool) {
    let coordinator = match AuditCoordinatorGuard::try_acquire() {
        Ok(Some(guard)) => guard,
        Ok(None) => {
            info!("audit dashboard snapshot in progress; deferring auditd verification");
            return;
        }
        Err(error) => {
            warn!("cannot acquire audit coordinator lock: {error:#}");
            return;
        }
    };

    let notification = verify_and_respond_locked(last_contained, store_missing_recorded);
    drop(coordinator);

    if let Some(event) = notification {
        notify_security_event(&event.kind, &event.message);
    }
}

fn verify_and_respond_locked(
    last_contained: &mut BTreeSet<String>,
    store_missing_recorded: &mut bool,
) -> Option<SecurityEvent> {
    match module_response::enforce_containment(false) {
        Ok(outcome) => {
            let next: BTreeSet<String> = outcome.module_ids.into_iter().collect();
            let mut notification = None;
            if outcome.audit_state == AuditStateAvailability::CleanUninitialized {
                *store_missing_recorded = false;
                last_contained.clear();
                return None;
            }
            if outcome.audit_state == AuditStateAvailability::Unavailable {
                if !*store_missing_recorded {
                    if let Err(error) =
                        global_audit::record_event(AuditEventKind::AuditStoreMissing)
                    {
                        warn!("failed to record audit store missing event: {error:#}");
                    }
                    notification = Some(SecurityEvent {
                        kind: "audit_store_missing".to_owned(),
                        message: "模块审计状态不可用，已执行全量隔离".to_owned(),
                    });
                    *store_missing_recorded = true;
                }
                warn!(
                    "module audit state is unavailable; fail-closed containment covers {} modules: {}",
                    next.len(),
                    outcome.audit_error.as_deref().unwrap_or("unknown error")
                );
                *last_contained = next;
                return notification;
            }

            *store_missing_recorded = false;
            if next != *last_contained {
                info!("audit containment set changed: {} modules", next.len());
                if let Err(error) = global_audit::record_event(AuditEventKind::ContainmentApplied {
                    module_ids: next.iter().cloned().collect(),
                }) {
                    warn!("failed to record audit containment event: {error:#}");
                }
                if !next.is_empty() {
                    notification = Some(SecurityEvent {
                        kind: "containment_applied".to_owned(),
                        message: format!(
                            "模块 {} 已隔离，请处理",
                            next.iter().cloned().collect::<Vec<_>>().join("、")
                        ),
                    });
                }
            }
            *last_contained = next;
            notification
        }
        Err(error) => {
            let mut notification = None;
            warn!("audit verification and containment failed: {error:#}");
            if !*store_missing_recorded {
                if let Err(record_error) =
                    global_audit::record_event(AuditEventKind::AuditStoreMissing)
                {
                    warn!("failed to record audit failure event: {record_error:#}");
                }
                notification = Some(SecurityEvent {
                    kind: "audit_store_missing".to_owned(),
                    message: "模块审计验证或全量隔离失败".to_owned(),
                });
                *store_missing_recorded = true;
            }
            if !last_contained.is_empty()
                && let Err(memory_error) =
                    module_response::enforce_memory_containment(last_contained)
            {
                warn!("failed to retain previous in-memory containment: {memory_error:#}");
            }
            notification
        }
    }
}

fn run_auditd_session(
    last_contained: &mut BTreeSet<String>,
    store_missing_recorded: &mut bool,
) -> Result<()> {
    let mut watcher = InotifyWatcher::new()?;
    watcher.refresh();

    loop {
        if watcher.needs_refresh {
            watcher.refresh();
        }

        verify_and_respond(last_contained, store_missing_recorded);

        let timeout_ms = i32::try_from(PERIODIC_VERIFY_INTERVAL.as_millis()).unwrap_or(i32::MAX);
        let mut poll_fd = libc::pollfd {
            fd: watcher.fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&raw mut poll_fd, 1, timeout_ms) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error).context("poll audit watches");
        }
        if ready == 0 {
            continue;
        }

        if poll_fd.revents & libc::POLLIN != 0 {
            let observed = watcher.drain_events()?;
            if watcher.needs_refresh {
                watcher.refresh();
            }
            if observed {
                thread::sleep(DEBOUNCE_DELAY);
            }
        } else if poll_fd.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
            watcher.needs_refresh = true;
            thread::sleep(DEBOUNCE_DELAY);
        }
    }
}

pub fn run_auditd() -> Result<()> {
    let _lock_guard = loop {
        if let Some(guard) = AuditdLockGuard::acquire()? {
            break guard;
        }
        info!("auditd lock is held; waiting for it to become available");
        thread::sleep(AUDITD_LOCK_WAIT);
    };
    if let Err(error) = std::fs::remove_dir_all(defs::AUDIT_INSTALL_SESSION_DIR)
        && error.kind() != io::ErrorKind::NotFound
    {
        warn!("failed to clean stale audit install sessions: {error:#}");
    }

    let mut last_contained = BTreeSet::new();
    let mut store_missing_recorded = false;
    loop {
        if let Err(error) = run_auditd_session(&mut last_contained, &mut store_missing_recorded) {
            warn!(
                "auditd session failed: {error:#}; restarting in {}s",
                AUDITD_RESTART_DELAY.as_secs()
            );
        }
        thread::sleep(AUDITD_RESTART_DELAY);
    }
}

pub fn spawn_auditd() -> Result<()> {
    if utils::create_daemon(true)? {
        let mut command = Command::new("/proc/self/exe");
        command
            .arg("auditd")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .current_dir("/");

        let error = command.exec();
        log::error!("failed to exec auditd: {error:#}");
        unsafe {
            libc::_exit(1);
        }
    }
    Ok(())
}

pub fn ensure_auditd_running() -> Result<()> {
    spawn_auditd()
}

fn install_session_dir(id: &str) -> Result<PathBuf> {
    ensure!(
        id.len() == 32
            && id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "invalid audit install session id"
    );
    Ok(Path::new(defs::AUDIT_INSTALL_SESSION_DIR).join(id))
}

pub fn begin_install_session(id: &str, timeout_seconds: u64) -> Result<()> {
    let session_dir = install_session_dir(id)?;
    let timeout = Duration::from_secs(timeout_seconds);
    ensure!(
        !timeout.is_zero() && timeout <= MAX_INSTALL_SESSION_TIMEOUT,
        "audit install session timeout must be between 1 and {} seconds",
        MAX_INSTALL_SESSION_TIMEOUT.as_secs()
    );
    utils::ensure_dir_exists(defs::AUDIT_INSTALL_SESSION_DIR)?;
    ensure!(
        !session_dir.exists(),
        "audit install session already exists"
    );
    utils::ensure_dir_exists(&session_dir)?;

    if utils::create_daemon(true)? {
        match run_install_session(&session_dir, timeout) {
            Ok(()) => {
                if let Err(error) = std::fs::remove_dir_all(&session_dir) {
                    warn!(
                        "failed to clean audit install session {}: {error:#}",
                        session_dir.display()
                    );
                }
            }
            Err(error) => {
                log::error!("audit install session failed: {error:#}");
                let message = format!("{error:#}");
                if let Err(write_error) = std::fs::write(session_dir.join("error"), message) {
                    log::error!("failed to persist audit install session error: {write_error:#}");
                }
            }
        }
        unsafe { libc::_exit(0) };
    }
    Ok(())
}

fn run_install_session(session_dir: &Path, timeout: Duration) -> Result<()> {
    let coordinator = AuditCoordinatorGuard::acquire_blocking()?;
    for entry in std::fs::read_dir(defs::AUDIT_INSTALL_SESSION_DIR)? {
        let path = entry?.path();
        ensure!(
            path == session_dir || !path.is_dir(),
            "another audit installation session is active"
        );
    }
    let stopped_services = stop_auditd_services()?;
    let resume_guard = AuditdResumeGuard {
        services: stopped_services,
    };
    let lock_deadline = std::time::Instant::now() + INSTALL_SESSION_LOCK_TIMEOUT;
    let auditd_lock = loop {
        if let Some(guard) = AuditdLockGuard::acquire()? {
            break guard;
        }
        ensure!(
            std::time::Instant::now() < lock_deadline,
            "auditd lock remained held after stopping init services; terminate duplicate or debug auditd processes"
        );
        thread::sleep(INSTALL_SESSION_POLL_INTERVAL);
    };
    drop(coordinator);

    utils::ensure_file_exists(session_dir.join("ready"))?;
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline && !session_dir.join("release").is_file() {
        thread::sleep(INSTALL_SESSION_POLL_INTERVAL);
    }

    drop(auditd_lock);
    drop(resume_guard);
    Ok(())
}

fn stop_auditd_services() -> Result<Vec<&'static str>> {
    let outcome = request_auditd_services_stop();
    ensure!(
        outcome.failures.is_empty(),
        "{}",
        outcome.failures.join("; ")
    );
    Ok(auditd_services_to_resume(&outcome))
}

fn request_auditd_services_stop() -> AuditdServiceStopOutcome {
    let services = ["ksud-auditd", "kernelsu_auditd"]
        .into_iter()
        .filter_map(|service| {
            utils::getprop(&format!("init.svc.{service}")).map(|state| (service, state))
        })
        .collect::<Vec<_>>();
    // A freshly generated modules.rc is not visible to Android init until the
    // next boot.  In that legitimate first-install state there is no service
    // to stop or resume.  The caller still has to acquire AUDITD_LOCK_PATH
    // before declaring the installation session ready, so an independently
    // running auditd (or a stale debug instance) cannot be bypassed here.
    if services.is_empty() {
        info!("no auditd init service is registered in the current boot");
        return AuditdServiceStopOutcome {
            services,
            active: Vec::new(),
            failures: Vec::new(),
        };
    }

    let active = services
        .iter()
        .filter(|(_, state)| matches!(state.as_str(), "running" | "restarting" | "stopping"))
        .map(|(service, _)| *service)
        .collect::<Vec<_>>();
    let mut failures = Vec::new();
    for (service, state) in &services {
        if matches!(state.as_str(), "running" | "restarting") {
            match Command::new("stop").arg(service).status() {
                Ok(status) if status.success() => {}
                Ok(status) => {
                    failures.push(format!("failed to stop auditd service {service}: {status}"));
                }
                Err(error) => {
                    failures.push(format!("stop auditd service {service}: {error}"));
                }
            }
        }
    }

    AuditdServiceStopOutcome {
        services,
        active,
        failures,
    }
}

fn auditd_services_to_resume(outcome: &AuditdServiceStopOutcome) -> Vec<&'static str> {
    let resume = if outcome.active.contains(&"ksud-auditd") {
        "ksud-auditd"
    } else if let Some(service) = outcome.active.first() {
        service
    } else if outcome
        .services
        .iter()
        .any(|(service, _)| *service == "ksud-auditd")
    {
        "ksud-auditd"
    } else {
        let Some((service, _)) = outcome.services.first() else {
            return Vec::new();
        };
        service
    };
    vec![resume]
}

pub fn stop_auditd_for_uninstall() -> Result<AuditdShutdownGuard> {
    let coordinator = AuditCoordinatorGuard::acquire_blocking()?;
    let outcome = request_auditd_services_stop();
    let lock_deadline = std::time::Instant::now() + INSTALL_SESSION_LOCK_TIMEOUT;
    loop {
        if let Some(auditd_lock) = AuditdLockGuard::acquire()? {
            for failure in outcome.failures {
                warn!("{failure}; auditd lock is free, continuing permanent uninstall");
            }
            return Ok(AuditdShutdownGuard {
                _auditd_lock: auditd_lock,
                _coordinator: coordinator,
            });
        }
        ensure!(
            std::time::Instant::now() < lock_deadline,
            "auditd remained active after stop request{}",
            if outcome.failures.is_empty() {
                String::new()
            } else {
                format!(": {}", outcome.failures.join("; "))
            }
        );
        thread::sleep(INSTALL_SESSION_POLL_INTERVAL);
    }
}

pub fn print_install_session_status(id: &str) -> Result<()> {
    let session_dir = install_session_dir(id)?;
    let error = std::fs::read_to_string(session_dir.join("error")).ok();
    println!(
        "{}",
        serde_json::json!({
            "ready": session_dir.join("ready").is_file(),
            "released": session_dir.join("release").is_file(),
            "error": error,
        })
    );
    Ok(())
}

pub fn install_session_active(id: &str) -> Result<bool> {
    let session_dir = install_session_dir(id)?;
    Ok(session_dir.join("ready").is_file() && !session_dir.join("release").exists())
}

pub fn release_install_session(id: &str) -> Result<()> {
    let session_dir = install_session_dir(id)?;
    if session_dir.join("error").is_file() {
        std::fs::remove_dir_all(&session_dir).context("clean failed audit install session")?;
        return Ok(());
    }
    ensure!(
        session_dir.join("ready").is_file(),
        "audit install session is not ready"
    );
    utils::ensure_file_exists(session_dir.join("release"))
}

pub fn record_restart_notify() {
    log::error!("auditd restarted by init");
    if let Err(error) = global_audit::record_event(AuditEventKind::AuditdRestart {
        reason: "init restarted auditd".to_owned(),
    }) {
        warn!("failed to record auditd restart event: {error:#}");
    }
    if let Err(error) = append_restart_marker() {
        warn!("failed to persist auditd restart marker: {error:#}");
    }
    notify_security_event("auditd_restart", "auditd 被重启");
}

fn notify_security_event(kind: &str, message: &str) {
    let Some(sender) = SECURITY_EVENT_SENDER
        .get_or_init(start_security_event_worker)
        .as_ref()
    else {
        return;
    };
    let event = SecurityEvent {
        kind: kind.to_owned(),
        message: message.to_owned(),
    };

    match sender.try_send(event) {
        Ok(()) => {}
        Err(TrySendError::Full(event)) => {
            warn!(
                "dropping audit security notification because its queue is full: {}",
                event.kind
            );
        }
        Err(TrySendError::Disconnected(event)) => {
            warn!(
                "dropping audit security notification because its worker stopped: {}",
                event.kind
            );
        }
    }
}

fn start_security_event_worker() -> Option<SyncSender<SecurityEvent>> {
    let (sender, receiver) = mpsc::sync_channel(SECURITY_EVENT_QUEUE_CAPACITY);
    match thread::Builder::new()
        .name("audit-notify".to_owned())
        .spawn(move || {
            for event in receiver {
                send_security_event(&event);
            }
        }) {
        Ok(_) => Some(sender),
        Err(error) => {
            warn!("failed to start audit security notification worker: {error:#}");
            None
        }
    }
}

fn send_security_event(event: &SecurityEvent) {
    let component = format!(
        "{}/me.weishu.kernelsu.ui.AuditEventReceiver",
        defs::DEFAULT_PACKAGE_NAME
    );
    let result = Command::new("/system/bin/am")
        .arg("broadcast")
        .arg("--user")
        .arg("0")
        .arg("-n")
        .arg(component)
        .arg("-a")
        .arg("me.weishu.kernelsu.action.AUDIT_SECURITY_EVENT")
        .arg("--es")
        .arg("kind")
        .arg(&event.kind)
        .arg("--es")
        .arg("message")
        .arg(&event.message)
        .status();

    match result {
        Ok(status) if status.success() => {}
        Ok(status) => warn!("audit security broadcast exited with status {status}"),
        Err(error) => warn!("failed to run audit security broadcast: {error:#}"),
    }
}

fn append_restart_marker() -> Result<()> {
    utils::ensure_dir_exists(defs::WORKING_DIR)?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(AUDITD_LOCK_MODE)
        .open(defs::AUDITD_RESTART_LOG_PATH)
        .with_context(|| format!("failed to open {}", defs::AUDITD_RESTART_LOG_PATH))?;
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock before unix epoch")?
        .as_secs();
    writeln!(file, "{timestamp}")?;
    Ok(())
}
