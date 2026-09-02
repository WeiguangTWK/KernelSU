use anyhow::Result;
#[cfg(target_os = "android")]
use anyhow::{Context, bail, ensure};
#[cfg(target_os = "android")]
use ksu_module_audit::sha256_path;
use ksu_module_audit::{AuditConfig, AuditReport, Severity, scan_zip_path};
#[cfg(target_os = "android")]
use std::fs::{File, OpenOptions};
#[cfg(target_os = "android")]
use std::io::{ErrorKind, Read};
#[cfg(target_os = "android")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "android")]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(target_os = "android")]
use std::path::Path;
#[cfg(any(target_os = "android", test))]
use std::time::Duration;
#[cfg(target_os = "android")]
use std::time::Instant;

#[cfg(target_os = "android")]
const EV_KEY: u16 = 0x01;
#[cfg(target_os = "android")]
const KEY_VOLUMEDOWN: u16 = 114;
#[cfg(target_os = "android")]
const KEY_VOLUMEUP: u16 = 115;
#[cfg(target_os = "android")]
const KEY_PRESSED: i32 = 1;
#[cfg(any(target_os = "android", test))]
const BASE_CONFIRM_TIMEOUT_SECONDS: u64 = 30;
#[cfg(any(target_os = "android", test))]
const PER_ADDITIONAL_FINDING_SECONDS: u64 = 4;
#[cfg(any(target_os = "android", test))]
const CRITICAL_MIN_TIMEOUT_SECONDS: u64 = 120;
#[cfg(any(target_os = "android", test))]
const MAX_CONFIRM_TIMEOUT_SECONDS: u64 = 300;
#[cfg(any(target_os = "android", test))]
const TIMEOUT_ROUND_SECONDS: u64 = 30;
const MAX_PRINTED_FINDINGS: usize = 200;

#[cfg(target_os = "android")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuditDecision {
    Continue,
    Abort,
}

#[cfg(target_os = "android")]
pub fn audit_before_install(zip: &str) -> Result<AuditReport> {
    println!("- Auditing module package");
    let report =
        scan_zip_path(zip, &AuditConfig::default()).context("static module audit failed")?;
    print_report(&report);

    if !report.requires_confirmation() {
        println!("- Static audit found no behavior requiring confirmation");
        return Ok(report);
    }

    let required_presses = report.required_confirmation_presses();
    let timeout = confirmation_timeout(&report);
    print_confirmation_prompt(&report, required_presses, timeout);
    let decision = wait_for_volume_decision(timeout, required_presses)
        .context("unable to read a confirmation from the volume keys")?;
    ensure!(
        decision == AuditDecision::Continue,
        "Installation aborted by user"
    );

    let current_hash = sha256_path(zip).context("recalculate module ZIP hash")?;
    ensure!(
        current_hash == report.package_sha256,
        "Module ZIP changed after static audit; installation aborted"
    );
    println!("- Audit warning accepted; continuing installation");
    Ok(report)
}

pub fn print_zip_report(zip: &str, json: bool) -> Result<()> {
    let report = scan_zip_path(zip, &AuditConfig::default())?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_report(&report);
    }
    Ok(())
}

fn print_report(report: &AuditReport) {
    println!("======== Module static audit ========");
    for finding in report.findings.iter().take(MAX_PRINTED_FINDINGS) {
        let severity = match finding.severity {
            Severity::Info => "INFO",
            Severity::Notice => "NOTICE",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        };
        let location = finding.line.map_or_else(
            || finding.path.clone(),
            |line| format!("{}:{line}", finding.path),
        );
        println!("[{severity}] {} ({})", finding.title, finding.rule_id);
        println!("  {location}");
        for step in &finding.provenance {
            println!("  -> {step}");
        }
        println!("  {}", single_line(&finding.evidence));
        println!();
    }
    if report.findings.len() > MAX_PRINTED_FINDINGS {
        println!(
            "! {} additional findings omitted from console output",
            report.findings.len() - MAX_PRINTED_FINDINGS
        );
        println!();
    }
    println!("======== Audit result ========");
    print_severity_count(report, Severity::Critical, "critical", "danger");
    print_severity_count(report, Severity::High, "high", "need review");
    println!("{} notice", report.count(Severity::Notice));
    println!("{} info", report.count(Severity::Info));
    println!(
        "Scanned {} files and {} decoded artifacts",
        report.scanned_files, report.derived_artifacts
    );
}

fn print_severity_count(report: &AuditReport, severity: Severity, label: &str, annotation: &str) {
    let count = report.count(severity);
    if count == 0 {
        println!("0 {label}");
    } else {
        println!(">> {count} {label} << {annotation}");
    }
}

#[cfg(target_os = "android")]
fn confirmation_timeout(report: &AuditReport) -> Duration {
    let displayed_findings = report.findings.len().min(MAX_PRINTED_FINDINGS);
    confirmation_timeout_for(displayed_findings, report.has_critical())
}

#[cfg(any(target_os = "android", test))]
fn confirmation_timeout_for(displayed_findings: usize, has_critical: bool) -> Duration {
    let additional_findings = displayed_findings.saturating_sub(1);
    let additional_seconds = u64::try_from(additional_findings)
        .unwrap_or(u64::MAX)
        .saturating_mul(PER_ADDITIONAL_FINDING_SECONDS);
    let mut seconds = BASE_CONFIRM_TIMEOUT_SECONDS.saturating_add(additional_seconds);
    seconds = seconds
        .div_ceil(TIMEOUT_ROUND_SECONDS)
        .saturating_mul(TIMEOUT_ROUND_SECONDS);
    if has_critical {
        seconds = seconds.max(CRITICAL_MIN_TIMEOUT_SECONDS);
    }
    Duration::from_secs(seconds.min(MAX_CONFIRM_TIMEOUT_SECONDS))
}

#[cfg(target_os = "android")]
fn print_confirmation_prompt(report: &AuditReport, required_presses: usize, timeout: Duration) {
    if report.has_critical() {
        println!("! Critical behavior may make the device unbootable or destroy data");
    } else {
        println!("! The module contains behavior that requires your acknowledgement");
    }
    if required_presses == 1 {
        println!("[VOL+] Continue installation");
    } else {
        println!("[VOL+] Press twice to continue installation");
    }
    println!("[VOL-] Abort installation");
    println!(
        "Installation will abort after {} seconds",
        timeout.as_secs()
    );
}

#[cfg(target_os = "android")]
fn wait_for_volume_decision(
    timeout: Duration,
    required_up_presses: usize,
) -> Result<AuditDecision> {
    let mut inputs = open_input_devices()?;
    ensure!(!inputs.is_empty(), "No readable /dev/input/event devices");
    drain_pending_events(&mut inputs);

    let start = Instant::now();
    let mut up_presses = 0_usize;
    loop {
        let remaining = timeout.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            bail!("Volume-key confirmation timed out; installation aborted");
        }
        let timeout_ms = i32::try_from(remaining.as_millis()).unwrap_or(i32::MAX);
        let mut poll_fds: Vec<_> = inputs
            .iter()
            .map(|input| libc::pollfd {
                fd: input.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        // SAFETY: poll_fds points to a live contiguous array for the duration of poll.
        let result = unsafe {
            libc::poll(
                poll_fds.as_mut_ptr(),
                libc::nfds_t::try_from(poll_fds.len()).unwrap_or(libc::nfds_t::MAX),
                timeout_ms,
            )
        };
        if result == 0 {
            bail!("Volume-key confirmation timed out; installation aborted");
        }
        if result < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == ErrorKind::Interrupted {
                continue;
            }
            return Err(error).context("poll input devices");
        }

        for (index, poll_fd) in poll_fds.iter().enumerate() {
            if poll_fd.revents & libc::POLLIN == 0 {
                continue;
            }
            while let Some((event_type, code, value)) = read_input_event(&mut inputs[index])? {
                if event_type != EV_KEY || value != KEY_PRESSED {
                    continue;
                }
                if code == KEY_VOLUMEDOWN {
                    return Ok(AuditDecision::Abort);
                }
                if code == KEY_VOLUMEUP {
                    up_presses += 1;
                    if up_presses >= required_up_presses {
                        return Ok(AuditDecision::Continue);
                    }
                    println!("- Confirmation {up_presses}/{required_up_presses}; press VOL+ again");
                }
            }
        }
    }
}

#[cfg(target_os = "android")]
fn open_input_devices() -> Result<Vec<File>> {
    let input_dir = Path::new("/dev/input");
    let mut inputs = Vec::new();
    for entry in std::fs::read_dir(input_dir)
        .context("read /dev/input")?
        .flatten()
    {
        let name = entry.file_name();
        if !name.to_string_lossy().starts_with("event") {
            continue;
        }
        if let Ok(file) = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(entry.path())
        {
            inputs.push(file);
        }
    }
    Ok(inputs)
}

#[cfg(target_os = "android")]
fn drain_pending_events(inputs: &mut [File]) {
    for input in inputs {
        while matches!(read_input_event(input), Ok(Some(_))) {}
    }
}

#[cfg(target_os = "android")]
fn read_input_event(input: &mut File) -> Result<Option<(u16, u16, i32)>> {
    const EVENT_SIZE: usize = std::mem::size_of::<libc::timeval>() + 8;
    let mut bytes = [0_u8; EVENT_SIZE];
    match input.read(&mut bytes) {
        Ok(0) => Ok(None),
        Ok(read) if read == EVENT_SIZE => {
            let offset = std::mem::size_of::<libc::timeval>();
            let event_type = u16::from_ne_bytes([bytes[offset], bytes[offset + 1]]);
            let code = u16::from_ne_bytes([bytes[offset + 2], bytes[offset + 3]]);
            let value = i32::from_ne_bytes([
                bytes[offset + 4],
                bytes[offset + 5],
                bytes[offset + 6],
                bytes[offset + 7],
            ]);
            Ok(Some((event_type, code, value)))
        }
        Ok(_) => bail!("short read from input device"),
        Err(error) if error.kind() == ErrorKind::WouldBlock => Ok(None),
        Err(error) => Err(error).context("read input event"),
    }
}

fn single_line(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confirmation_timeout_scales_with_output_length() {
        assert_eq!(confirmation_timeout_for(1, false), Duration::from_secs(30));
        assert_eq!(
            confirmation_timeout_for(17, false),
            Duration::from_secs(120)
        );
        assert_eq!(
            confirmation_timeout_for(67, false),
            Duration::from_secs(300)
        );
        assert_eq!(
            confirmation_timeout_for(200, false),
            Duration::from_secs(300)
        );
    }

    #[test]
    fn critical_findings_get_at_least_two_minutes() {
        assert_eq!(confirmation_timeout_for(1, true), Duration::from_secs(120));
    }
}
