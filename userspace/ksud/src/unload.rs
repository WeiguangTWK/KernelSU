use anyhow::{Context, Result, bail, ensure};
use log::{info, warn};
use std::collections::BTreeSet;
use std::fs;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use crate::utils;

const CLIENT_QUIESCE_TIMEOUT: Duration = Duration::from_secs(5);
const MODULE_UNLOAD_TIMEOUT: Duration = Duration::from_secs(5);
const UNLOAD_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Find PIDs of processes running in the KernelSU su domain (u:r:ksu:s0).
/// Returns a list of PIDs excluding our own.
fn find_su_domain_pids() -> Vec<i32> {
    let my_pid = std::process::id() as i32;
    let mut pids = Vec::new();

    let Ok(entries) = fs::read_dir("/proc") else {
        return pids;
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<i32>().ok()) else {
            continue;
        };
        if pid == my_pid {
            continue;
        }

        let attr_path = format!("/proc/{pid}/attr/current");
        if let Ok(context) = fs::read_to_string(&attr_path) {
            let context = context.trim().trim_end_matches('\0');
            if context == "u:r:ksu:s0" {
                pids.push(pid);
            }
        }
    }

    pids
}

/// Find PIDs of processes holding ksu_driver or ksu_fdwrapper file descriptors.
/// Returns a list of PIDs excluding our own.
fn find_ksu_fd_holders() -> Vec<i32> {
    let my_pid = std::process::id() as i32;
    let mut pids = Vec::new();

    let Ok(entries) = fs::read_dir("/proc") else {
        return pids;
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<i32>().ok()) else {
            continue;
        };
        if pid == my_pid {
            continue;
        }

        let fd_dir = format!("/proc/{pid}/fd");
        let Ok(fds) = fs::read_dir(&fd_dir) else {
            continue;
        };

        for fd_entry in fds.flatten() {
            let link_path = fd_entry.path();
            if let Ok(target) = fs::read_link(&link_path) {
                let target_str = target.to_string_lossy();
                if target_str.contains("[ksu_driver]") || target_str.contains("[ksu_fdwrapper]") {
                    pids.push(pid);
                    break;
                }
            }
        }
    }

    pids
}

fn kill_pids(pids: &[i32], signal: i32) {
    for &pid in pids {
        unsafe {
            libc::kill(pid, signal);
        }
    }
}

fn remaining_ksu_client_pids() -> Vec<i32> {
    find_su_domain_pids()
        .into_iter()
        .chain(find_ksu_fd_holders())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn terminate_ksu_clients() -> Result<()> {
    let deadline = Instant::now() + CLIENT_QUIESCE_TIMEOUT;

    loop {
        let pids = remaining_ksu_client_pids();
        if pids.is_empty() {
            return Ok(());
        }

        info!(
            "unload: terminating {} remaining KernelSU client processes: {pids:?}",
            pids.len()
        );
        kill_pids(&pids, libc::SIGKILL);

        if Instant::now() >= deadline {
            bail!("KernelSU client processes did not quiesce before timeout: {pids:?}");
        }
        thread::sleep(UNLOAD_POLL_INTERVAL);
    }
}

/// Close all ksu_driver and ksu_fdwrapper fds held by the current process.
fn close_ksu_fds() {
    let Ok(entries) = fs::read_dir("/proc/self/fd") else {
        return;
    };

    for entry in entries.flatten() {
        let Ok(fd) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        if let Ok(target) = fs::read_link(entry.path()) {
            let target_str = target.to_string_lossy();
            if target_str.contains("[ksu_driver]") || target_str.contains("[ksu_fdwrapper]") {
                info!("unload: closing fd {fd} -> {target_str}");
                unsafe {
                    libc::close(fd);
                }
            }
        }
    }
}

fn delete_kernelsu_module() -> Result<()> {
    let deadline = Instant::now() + MODULE_UNLOAD_TIMEOUT;
    let mut attempt = 1_u32;

    loop {
        match rustix::system::delete_module(c"kernelsu", 0) {
            Ok(()) => return Ok(()),
            Err(error) if error == rustix::io::Errno::AGAIN && Instant::now() < deadline => {
                let pids = remaining_ksu_client_pids();
                if !pids.is_empty() {
                    warn!(
                        "unload: module is still referenced; terminating clients before attempt {}: {pids:?}",
                        attempt + 1
                    );
                    kill_pids(&pids, libc::SIGKILL);
                } else {
                    warn!(
                        "unload: module is still referenced with no visible client; retrying attempt {}",
                        attempt + 1
                    );
                }
                attempt += 1;
                thread::sleep(UNLOAD_POLL_INTERVAL);
            }
            Err(error) => {
                bail!("delete_module kernelsu failed after {attempt} attempt(s): {error}");
            }
        }
    }
}

fn set_android_services(command: &str) -> Result<()> {
    let status = Command::new(command)
        .status()
        .with_context(|| format!("run Android {command}"))?;
    ensure!(status.success(), "Android {command} failed: {status}");
    Ok(())
}

fn recover_services() {
    info!("unload: restarting Android services after failed unload...");
    if let Err(error) = set_android_services("start") {
        warn!("unload: failed to restart Android services: {error:#}");
    }
}

pub fn unload() -> Result<()> {
    info!("unload: starting KernelSU unload sequence");

    // 0. Switch cgroups so we don't get killed along with our parent shell
    utils::switch_cgroups();

    // 1. Stop auditd explicitly. It is a disabled init service and is not
    // covered reliably by Android's global stop/start commands.
    info!("unload: stopping audit daemon...");
    let auditd_shutdown = crate::auditd::stop_auditd_for_uninstall()
        .context("stop audit daemon before unloading KernelSU")?;

    // 2. stop (Android init stop command - stops all services)
    info!("unload: stopping Android services...");
    let unload_result = (|| -> Result<()> {
        set_android_services("stop")?;

        // 3. Close our visible driver descriptors before waiting for every
        // other KernelSU client to exit.
        info!("unload: closing all visible local ksu fds...");
        close_ksu_fds();

        info!("unload: quiescing KernelSU client processes...");
        terminate_ksu_clients()?;

        // 4. delete_module("kernelsu") with a bounded EAGAIN retry window.
        info!("unload: removing kernelsu module...");
        delete_kernelsu_module()
    })();

    if let Err(error) = unload_result {
        recover_services();
        auditd_shutdown.resume_after_failed_shutdown();
        return Err(error);
    }

    // 5. start (Android init start command - restarts all services). Auditd
    // remains stopped because its disabled service is not part of global start.
    info!("unload: restarting Android services...");
    if let Err(error) = set_android_services("start") {
        warn!("unload: KernelSU was removed but Android services failed to restart: {error:#}");
    }

    // 6. Exit without restarting auditd after the module has been removed.
    drop(auditd_shutdown);
    info!("unload: done, exiting ksud");
    Ok(())
}
