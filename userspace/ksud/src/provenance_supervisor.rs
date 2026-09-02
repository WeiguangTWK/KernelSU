use crate::{ksu_uapi, ksucalls, provenance_io_uring};
use anyhow::{Context, Result, bail, ensure};
use log::{info, warn};
use sha2::{Digest, Sha256};
use std::os::fd::RawFd;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

const READINESS_TIMEOUT: Duration = Duration::from_secs(10);
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
const POLL_INTERVAL: Duration = Duration::from_millis(20);
const SELFTEST_LAUNCH_TIMEOUT_MS: u32 = 5_000;

fn parse_nonce(value: &str) -> Result<[u8; 16]> {
    ensure!(
        value.len() == 32,
        "boot claim nonce must contain 32 hex digits"
    );
    let mut nonce = [0_u8; 16];
    base16ct::lower::decode(value, &mut nonce)
        .map_err(|_| anyhow::anyhow!("boot claim nonce is not lowercase hexadecimal"))?;
    ensure!(
        nonce.iter().any(|byte| *byte != 0),
        "boot claim nonce is zero"
    );
    Ok(nonce)
}

fn digest(label: &[u8]) -> [u8; 32] {
    Sha256::digest(label).into()
}

fn selftest_descriptor() -> ksu_uapi::ksu_provenance_context_descriptor_v1 {
    ksu_uapi::ksu_provenance_context_descriptor_v1 {
        size: std::mem::size_of::<ksu_uapi::ksu_provenance_context_descriptor_v1>() as u16,
        version: ksu_uapi::KSU_PROVENANCE_UAPI_VERSION,
        flags: 0,
        stage: ksu_uapi::ksu_provenance_stage_KSU_PROVENANCE_STAGE_ACTION,
        reserved0: 0,
        actor_id: digest(b"KernelSU Phase 3 lifecycle self-test actor"),
        subject_id: digest(b"KernelSU Phase 3 lifecycle self-test subject"),
        controller_id: [0; 32],
        script_sha256: digest(b"KernelSU Phase 3 lifecycle self-test payload"),
        operation_id: digest(b"KernelSU Phase 3 lifecycle self-test operation"),
        reserved1: [0; 48],
    }
}

fn verify_current_context(generation: u64, cookie: u64) -> Result<()> {
    let current =
        ksucalls::get_current_provenance_context().context("query current provenance context")?;
    ensure!(
        current.supervisor_generation == generation,
        "provenance generation changed: expected {generation}, got {}",
        current.supervisor_generation
    );
    ensure!(
        current.context_cookie == cookie,
        "provenance cookie changed: expected {cookie:#x}, got {:#x}",
        current.context_cookie
    );
    ensure!(
        current.gap_reason == ksu_uapi::ksu_provenance_gap_reason_KSU_PROVENANCE_GAP_NONE,
        "provenance payload acquired gap {}",
        current.gap_reason
    );
    Ok(())
}

fn verify_isolation(supervisor_pid: i32) -> Result<()> {
    ensure!(supervisor_pid > 0, "invalid provenance supervisor pid");
    let signal_result = unsafe { libc::kill(supervisor_pid, 0) };
    ensure!(
        signal_result == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM),
        "tagged payload was not denied signal access to provenance supervisor"
    );

    match ksucalls::get_feature(0) {
        Err(error) if error.raw_os_error() == Some(libc::EPERM) => Ok(()),
        Err(error) => Err(error).context("tagged sensitive supercall isolation"),
        Ok(_) => bail!("tagged payload reached a sensitive KernelSU supercall"),
    }
}

pub fn run_payload(generation: u64, cookie: u64, depth: u8, supervisor_pid: i32) -> Result<()> {
    verify_current_context(generation, cookie)?;
    if depth == 0 {
        provenance_io_uring::run_all(generation, cookie)
            .context("qualify Phase 3 io_uring attribution")?;
    }
    verify_isolation(supervisor_pid)?;

    let thread_check = thread::spawn(move || verify_current_context(generation, cookie));
    thread_check
        .join()
        .map_err(|_| anyhow::anyhow!("provenance self-test thread panicked"))??;

    let keep_caps = unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0) };
    if keep_caps != 0 {
        return Err(std::io::Error::last_os_error()).context("PR_SET_KEEPCAPS self-test");
    }
    verify_current_context(generation, cookie)?;
    let restore_caps = unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 0, 0, 0, 0) };
    if restore_caps != 0 {
        return Err(std::io::Error::last_os_error())
            .context("restore PR_SET_KEEPCAPS after self-test");
    }
    verify_current_context(generation, cookie)?;

    if depth == 0 {
        let executable = std::env::current_exe().context("resolve ksud self-test executable")?;
        let status = Command::new(executable)
            .arg("provenance-payload")
            .arg("--generation")
            .arg(generation.to_string())
            .arg("--cookie")
            .arg(cookie.to_string())
            .arg("--depth")
            .arg("1")
            .arg("--supervisor-pid")
            .arg(supervisor_pid.to_string())
            .status()
            .context("run inherited fork/exec provenance payload")?;
        ensure!(
            status.success(),
            "nested provenance payload failed: {status}"
        );
        verify_current_context(generation, cookie)?;
    }
    Ok(())
}

fn close_fd(fd: RawFd) {
    if fd >= 0 {
        unsafe {
            libc::close(fd);
        }
    }
}

fn run_launch_selftest(supervisor_fd: RawFd, generation: u64) -> Result<()> {
    let launch = ksucalls::create_provenance_launch(
        supervisor_fd,
        selftest_descriptor(),
        SELFTEST_LAUNCH_TIMEOUT_MS,
    )
    .context("create one-use Phase 3 self-test launch")?;
    let executable = std::env::current_exe().context("resolve ksud supervisor executable")?;
    let launch_fd = launch.endpoint_fd;
    let cookie = launch.context_cookie;
    let supervisor_pid = std::process::id();

    let mut command = Command::new(executable);
    command
        .arg("provenance-payload")
        .arg("--generation")
        .arg(generation.to_string())
        .arg("--cookie")
        .arg(cookie.to_string())
        .arg("--depth")
        .arg("0")
        .arg("--supervisor-pid")
        .arg(supervisor_pid.to_string());
    unsafe {
        command.pre_exec(move || {
            ksucalls::activate_provenance_launch(launch_fd, generation, cookie)?;
            match ksucalls::activate_provenance_launch(launch_fd, generation, cookie) {
                Err(error) if error.raw_os_error() == Some(libc::EALREADY) => Ok(()),
                Err(error) => Err(error),
                Ok(_) => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "one-use provenance launch endpoint accepted replay",
                )),
            }
        });
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            close_fd(launch_fd);
            let _ = ksucalls::close_provenance_context(supervisor_fd, generation, cookie);
            return Err(error).context("spawn activated Phase 3 self-test payload");
        }
    };
    close_fd(launch_fd);
    let status = child.wait().context("wait for Phase 3 self-test payload")?;
    let close_result = ksucalls::close_provenance_context(supervisor_fd, generation, cookie);
    ensure!(
        status.success(),
        "Phase 3 self-test payload failed: {status}"
    );
    close_result.context("close Phase 3 self-test context")?;

    let deadline = Instant::now() + DRAIN_TIMEOUT;
    loop {
        let status =
            ksucalls::get_provenance_context_status().context("query Phase 3 self-test drain")?;
        if status.active_contexts == 0
            && status.task_bindings == 0
            && status.credential_bindings == 0
            && status.pending_launches == 0
        {
            ensure!(
                status.last_gap_reason
                    == ksu_uapi::ksu_provenance_gap_reason_KSU_PROVENANCE_GAP_NONE,
                "Phase 3 self-test recorded gap {}",
                status.last_gap_reason
            );
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!(
                "Phase 3 context did not drain: contexts={} tasks={} creds={} launches={}",
                status.active_contexts,
                status.task_bindings,
                status.credential_bindings,
                status.pending_launches
            );
        }
        thread::sleep(POLL_INTERVAL);
    }
}

pub fn run_supervisor(boot_claim_nonce: &str) -> Result<()> {
    ksucalls::ensure_uapi_version_matched()?;
    let nonce = parse_nonce(boot_claim_nonce)?;
    let eligibility =
        ksucalls::get_provenance_eligibility_info().context("query supervisor exec eligibility")?;
    ksucalls::expect_provenance_claim_not_ready(eligibility.eligibility_generation)
        .context("reject wrong boot claim nonce")?;
    let claim = ksucalls::claim_provenance_supervisor(eligibility.eligibility_generation, nonce)
        .context("claim provenance supervisor")?;
    match ksucalls::claim_provenance_supervisor(eligibility.eligibility_generation, nonce) {
        Err(error) if error.raw_os_error() == Some(libc::EALREADY) => {}
        Err(error) => return Err(error).context("reject replayed boot claim nonce"),
        Ok(replayed) => {
            close_fd(replayed.endpoint_fd);
            bail!("replayed boot claim nonce created a second supervisor endpoint");
        }
    }
    let supervisor_fd = claim.endpoint_fd;
    let status = match ksucalls::get_provenance_context_status() {
        Ok(status) => status,
        Err(error) => {
            close_fd(supervisor_fd);
            return Err(error).context("query claimed provenance supervisor generation");
        }
    };
    if status.supervisor_state
        != ksu_uapi::ksu_provenance_supervisor_state_KSU_PROVENANCE_SUPERVISOR_CLAIMED
        || status.supervisor_generation == 0
    {
        close_fd(supervisor_fd);
        bail!(
            "invalid claimed provenance supervisor state={}, generation={}",
            status.supervisor_state,
            status.supervisor_generation
        );
    }
    let generation = status.supervisor_generation;

    if let Err(error) = run_launch_selftest(supervisor_fd, generation) {
        close_fd(supervisor_fd);
        return Err(error).context("Phase 3 lifecycle self-test");
    }
    ksucalls::mark_provenance_supervisor_ready(supervisor_fd, generation)
        .context("publish Phase 3 supervisor readiness")?;
    info!("Phase 3 provenance supervisor ready, generation={generation}");

    loop {
        unsafe {
            libc::pause();
        }
        warn!("provenance supervisor pause returned after signal");
    }
}

pub fn report_eligible_stage() -> Result<()> {
    ksucalls::ensure_uapi_version_matched()?;
    ksucalls::report_post_fs_data_checked().context("report provenance post-fs-data stage")?;
    Ok(())
}

pub fn wait_for_ready() -> Result<()> {
    let info = ksucalls::get_provenance_info()?;
    if info.provider_state
        == ksu_uapi::ksu_provenance_provider_state_KSU_PROVENANCE_PROVIDER_DISABLED
    {
        return Ok(());
    }
    let claim_capability = ksu_uapi::KSU_PROVENANCE_CAP_SUPERVISOR_CLAIM;
    if info.operational_capabilities & claim_capability == 0 {
        bail!(
            "provenance is configured but its Phase 3 provider is unavailable (state={})",
            info.provider_state
        );
    }

    let deadline = Instant::now() + READINESS_TIMEOUT;
    loop {
        let status = ksucalls::get_provenance_context_status()?;
        if status.supervisor_state
            == ksu_uapi::ksu_provenance_supervisor_state_KSU_PROVENANCE_SUPERVISOR_READY
        {
            ensure!(
                status.last_gap_reason
                    == ksu_uapi::ksu_provenance_gap_reason_KSU_PROVENANCE_GAP_NONE,
                "provenance supervisor ready with gap {}",
                status.last_gap_reason
            );
            return Ok(());
        }
        if status.supervisor_state
            == ksu_uapi::ksu_provenance_supervisor_state_KSU_PROVENANCE_SUPERVISOR_LOST
            || status.supervisor_state
                == ksu_uapi::ksu_provenance_supervisor_state_KSU_PROVENANCE_SUPERVISOR_FAILED
        {
            bail!(
                "provenance supervisor entered failure state {}",
                status.supervisor_state
            );
        }
        if Instant::now() >= deadline {
            bail!(
                "provenance supervisor readiness timed out in state {}",
                status.supervisor_state
            );
        }
        thread::sleep(POLL_INTERVAL);
    }
}
