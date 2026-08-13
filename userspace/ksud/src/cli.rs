use anyhow::{Context, Ok, Result};
use clap::Parser;
use std::io::Write;
use std::path::PathBuf;

use android_logger::Config;
use log::{LevelFilter, error, info};

use crate::boot_patch::{BootPatchArgs, BootRestoreArgs};
use crate::lkm_image::BootPatchV2Args;
use crate::module::regenerate_preinit_rc;
use crate::{
    apk_sign, assets, auditd, debug, defs, init_event, ksu_uapi, ksucalls, module, module_config,
    sulog, utils,
};

/// KernelSU userspace cli
#[derive(Parser, Debug)]
#[command(author, version = defs::FULL_VERSION, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    /// Manage KernelSU modules
    Module {
        #[command(subcommand)]
        command: Module,
    },

    /// Trigger `post-fs-data` event
    PostFsData,

    /// Trigger `service` event
    Services,

    /// Run sulog reader daemon. Not for user. Use `ksud debug sulogd` to launch daemon.
    #[command(hide = true)]
    Sulogd,

    /// Run module audit watcher daemon. Not for user. Use `ksud debug auditd` to launch daemon.
    #[command(hide = true)]
    Auditd,

    /// Record an auditd restart security event.
    #[command(hide = true)]
    AuditdRestartNotify,

    /// Trigger `boot-complete` event
    BootCompleted,

    /// Load kernelsu.ko and execute late-load stage scripts
    LateLoad {
        /// Use adb root to execute late-load for jailbreaking by Magica
        #[arg(long, default_missing_value = "5555", num_args = 0..=1)]
        magica: Option<u16>,

        /// Pass allow_shell=1 when loading kernelsu.ko
        #[arg(long)]
        allow_shell: bool,

        /// Restore adb properties after magica late-load
        #[arg(long)]
        post_magica: bool,

        /// Specify kernel KMI version instead of auto-detection
        #[arg(long)]
        kmi: Option<String>,

        /// manager package name
        #[arg(long, default_value_t = String::from(defs::DEFAULT_PACKAGE_NAME))]
        package_name: String,
    },

    /// Emulate system reboot
    SoftReboot,

    /// Load a kernel module with kallsyms access
    Insmod {
        /// kernel module path
        module: PathBuf,
        /// module load parameters (e.g. key=val key2=val2)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        params: Vec<String>,
    },

    /// Install KernelSU userspace component to system
    Install {
        #[arg(long, default_value = None)]
        libadbroot: Option<PathBuf>,

        #[arg(long, default_value = None)]
        data_path: Option<PathBuf>,
    },

    /// Unload KernelSU kernel module (LKM Only)
    Unload,

    /// Uninstall KernelSU modules and itself(LKM Only)
    Uninstall {
        #[arg(long, default_value_t = String::from(defs::DEFAULT_PACKAGE_NAME))]
        package_name: String,
    },

    /// SELinux policy Patch tool
    Sepolicy {
        #[command(subcommand)]
        command: Sepolicy,
    },

    /// Manage App Profiles
    Profile {
        #[command(subcommand)]
        command: Profile,
    },

    /// Manage kernel features
    Feature {
        #[command(subcommand)]
        command: Feature,
    },

    /// Patch boot or init_boot images to apply KernelSU
    BootPatch(BootPatchArgs),

    /// Restore boot or init_boot images patched by KernelSU
    BootRestore(BootRestoreArgs),

    /// Patch KernelSU into a boot image
    ///
    /// Always operates on a boot image; never selects init_boot or vendor_boot.
    BootPatchV2(BootPatchV2Args),

    /// Show boot information
    BootInfo {
        #[command(subcommand)]
        command: BootInfo,
    },
    /// For developers
    Debug {
        #[command(subcommand)]
        command: Debug,
    },
    /// Kernel interface
    Kernel {
        #[command(subcommand)]
        command: Kernel,
    },

    /// Resetprop - Magisk-compatible system property tool
    #[command(disable_help_flag = true)]
    Resetprop {
        /// Arguments passed to resetprop
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<String>,
    },

    /// Manage initrc injection
    Initrc {
        #[command(subcommand)]
        command: Initrc,
    },
}

#[derive(clap::Subcommand, Debug)]
enum BootInfo {
    /// show current kmi version
    CurrentKmi,

    /// show supported kmi versions
    SupportedKmis,

    /// check if device is A/B capable
    IsAbDevice,

    /// show auto-selected boot partition name
    DefaultPartition,

    /// list available partitions for current or OTA toggled slot
    AvailablePartitions,

    /// show slot suffix for current or OTA toggled slot
    SlotSuffix {
        /// toggle to another slot
        #[arg(short = 'u', long, default_value = "false")]
        ota: bool,
    },
}

#[derive(clap::Subcommand, Debug)]
enum Debug {
    /// Set the manager app, kernel CONFIG_KSU_DEBUG should be enabled.
    SetManager {
        /// manager package name
        #[arg(default_value_t = String::from(defs::DEFAULT_PACKAGE_NAME))]
        apk: String,
    },

    /// Get apk size and hash
    GetSign {
        /// apk path
        apk: String,
    },

    /// Root Shell
    Su {
        /// switch to gloabl mount namespace
        #[arg(short, long, default_value = "false")]
        global_mnt: bool,
    },

    /// Get kernel version
    Version,

    /// For testing
    Test,

    /// Extract an embedded binary to a specified path
    ExtractBinary {
        /// binary name (e.g. busybox, resetprop, bootctl)
        name: String,
        /// destination file path
        path: PathBuf,
    },

    /// Process mark management
    Mark {
        #[command(subcommand)]
        command: MarkCommand,
    },

    /// Launch sulogd daemon manually
    Sulogd,

    /// Launch auditd daemon manually
    Auditd,

    /// Get kernel info
    Info,

    /// Print default package name
    Package,
}

#[derive(clap::Subcommand, Debug)]
enum MarkCommand {
    /// Get mark status for a process (or all)
    Get {
        /// target pid (0 for total count)
        #[arg(default_value = "0")]
        pid: i32,
    },

    /// Mark a process
    Mark {
        /// target pid (0 for all processes)
        #[arg(default_value = "0")]
        pid: i32,
    },

    /// Unmark a process
    Unmark {
        /// target pid (0 for all processes)
        #[arg(default_value = "0")]
        pid: i32,
    },

    /// Refresh mark for all running processes
    Refresh,
}

#[derive(clap::Subcommand, Debug)]
enum Sepolicy {
    /// Patch sepolicy
    Patch {
        /// sepolicy statements
        sepolicy: String,
    },

    /// Apply sepolicy from file
    Apply {
        /// sepolicy file path
        file: String,
    },

    /// Check if sepolicy statement is supported/valid
    Check {
        /// sepolicy statements
        sepolicy: String,
    },
}

#[derive(clap::Subcommand, Debug)]
enum Module {
    /// Install module <ZIP>
    Install {
        /// module zip file path
        zip: String,
    },

    /// Audit a module ZIP without installing it
    Audit {
        /// module zip file path
        zip: String,
        /// print the structured JSON report
        #[arg(long)]
        json: bool,
    },

    /// Verify persisted module audit history
    AuditHistory {
        /// limit verification to one module id
        #[arg(long)]
        id: Option<String>,
        /// print structured JSON
        #[arg(long)]
        json: bool,
    },

    /// Verify persisted module audit state without returning event payloads
    AuditStatus {
        /// print structured JSON
        #[arg(long)]
        json: bool,
    },

    /// Stream a consolidated Security & Audit Center dashboard as JSON Lines
    AuditDashboard,

    /// Wait briefly for the audit store to change, then request re-verification
    AuditWatch {
        #[arg(long)]
        baseline: String,
        #[arg(long, default_value_t = 30)]
        timeout_seconds: u64,
    },

    /// Diagnose damage to events anchored by the Manager audit seal
    AuditRecoveryStatus {
        /// print structured JSON
        #[arg(long)]
        json: bool,
    },

    /// Export the canonical payload for a Manager Keystore checkpoint
    AuditCheckpoint,

    /// Manage Manager-signed authorization for audit mutations
    AuditAuth {
        #[command(subcommand)]
        command: AuditAuth,
    },

    /// Persist and verify Manager Keystore-signed audit checkpoints
    AuditSeal {
        #[command(subcommand)]
        command: AuditSeal,
    },

    /// Rescan every installed module and append authenticated audit events
    AuditRescan {
        /// print structured JSON results
        #[arg(long)]
        json: bool,
        /// one-shot Manager authorization token
        #[arg(long)]
        authorization: String,
    },

    /// List or clear audit histories whose modules are no longer installed
    AuditPrune {
        /// only clear one stale module history
        #[arg(long)]
        id: Option<String>,
        /// list eligible histories without clearing them
        #[arg(long)]
        dry_run: bool,
        /// print structured JSON results
        #[arg(long)]
        json: bool,
        /// one-shot Manager authorization token (required unless --dry-run)
        #[arg(long)]
        authorization: Option<String>,
    },

    /// Disable an untrusted module and cancel its normal scripted uninstall
    AuditContain {
        /// untrusted module id
        id: String,
    },

    /// Remove an untrusted module without executing module-controlled scripts
    AuditSecureRemove {
        /// untrusted module id
        id: String,
        /// print structured JSON result
        #[arg(long)]
        json: bool,
        /// one-shot Manager authorization token
        #[arg(long)]
        authorization: String,
    },

    /// Rebuild a damaged Manager-sealed module history in KernelSU safe mode
    AuditRecoverSealed {
        /// affected module id
        id: String,
        /// print structured JSON
        #[arg(long)]
        json: bool,
        /// one-shot Manager authorization token
        #[arg(long)]
        authorization: String,
    },

    /// Query response prerequisites without reading the audit store
    AuditResponseStatus,

    /// Undo module uninstall mark <id>
    UndoUninstall {
        /// module id
        id: String,
    },

    /// Uninstall module <id>
    Uninstall {
        /// module id
        id: String,
    },

    /// enable module <id>
    Enable {
        /// module id
        id: String,
    },

    /// disable module <id>
    Disable {
        // module id
        id: String,
    },

    /// run action for module <id>
    Action {
        // module id
        id: String,
    },

    /// list all modules
    List,

    /// manage module configuration
    Config {
        /// target internal module name (resolved as internal.<name>)
        #[arg(long)]
        internal: Option<String>,
        #[command(subcommand)]
        command: ModuleConfigCmd,
    },
}

#[derive(clap::Subcommand, Debug)]
enum AuditAuth {
    /// Show the registered Manager key and current audit inventory
    Status,
    /// Trust the first Manager key for audit mutations
    Register {
        /// uncompressed P-256 public key encoded as hexadecimal
        #[arg(long)]
        public_key: String,
    },
    /// Replace a missing or mismatched Manager key in kernel safe mode
    Recover {
        /// uncompressed P-256 public key encoded as hexadecimal
        #[arg(long)]
        public_key: String,
    },
    /// Create a state-bound challenge for one audit mutation
    Challenge {
        /// supported action: rescan or prune
        action: String,
        /// optional stale module id for a targeted prune
        #[arg(long)]
        id: Option<String>,
    },
}

#[derive(clap::Subcommand, Debug)]
enum AuditSeal {
    /// Show the latest verified Manager seal
    Status,
    /// Commit the current Manager checkpoint envelope as the next seal
    Commit {
        /// file containing the UTF-8 checkpoint envelope encoded as hexadecimal
        #[arg(long)]
        file: std::path::PathBuf,
    },
}

#[derive(clap::Subcommand, Debug)]
enum ModuleConfigCmd {
    /// Get a config value
    Get {
        /// config key
        key: String,
    },

    /// Set a config value
    Set {
        /// config key
        key: String,
        /// config value (omit to read from stdin)
        value: Option<String>,
        /// read value from stdin (default if value not provided)
        #[arg(long)]
        stdin: bool,
        /// use temporary config (cleared on reboot)
        #[arg(short, long)]
        temp: bool,
    },

    /// List all config entries
    List,

    /// Delete a config entry
    Delete {
        /// config key
        key: String,
        /// delete from temporary config
        #[arg(short, long)]
        temp: bool,
    },

    /// Clear all config entries
    Clear {
        /// clear temporary config
        #[arg(short, long)]
        temp: bool,
    },
}

#[derive(clap::Subcommand, Debug)]
enum Profile {
    /// get root profile's selinux policy of <package-name>
    GetSepolicy {
        /// package name
        package: String,
    },

    /// set root profile's selinux policy of <package-name> to <profile>
    SetSepolicy {
        /// package name
        package: String,
        /// policy statements
        policy: String,
    },

    /// get template of <id>
    GetTemplate {
        /// template id
        id: String,
    },

    /// set template of <id> to <template string>
    SetTemplate {
        /// template id
        id: String,
        /// template string
        template: String,
    },

    /// delete template of <id>
    DeleteTemplate {
        /// template id
        id: String,
    },

    /// list all templates
    ListTemplates,
}

#[derive(clap::Subcommand, Debug)]
enum Feature {
    /// Get feature value and support status
    Get {
        /// Feature ID or name (su_compat, kernel_umount, sulog, adb_root, selinux_hide)
        id: String,
        /// Read from config file
        #[arg(long, default_value_t = false)]
        config: bool,
    },

    /// Set feature value
    Set {
        /// Feature ID or name
        id: String,
        /// Feature value (0=disable, 1=enable)
        value: u64,
    },

    /// List all available features
    List,

    /// Check feature status (supported/unsupported/managed)
    Check {
        /// Feature ID or name (su_compat, kernel_umount, sulog, adb_root, selinux_hide)
        id: String,
    },

    /// Load configuration from file and apply to kernel
    Load,

    /// Save current kernel feature states to file
    Save,
}

#[derive(clap::Subcommand, Debug)]
enum Kernel {
    /// Nuke ext4 sysfs
    NukeExt4Sysfs {
        /// mount point
        mnt: String,
    },
    /// Manage umount list
    Umount {
        #[command(subcommand)]
        command: UmountOp,
    },
    /// Notify that module is mounted
    NotifyModuleMounted,
}

#[derive(clap::Subcommand, Debug)]
enum UmountOp {
    /// Add mount point to umount list
    Add {
        /// mount point path
        mnt: String,
        /// umount flags (default: 0, MNT_DETACH: 2)
        #[arg(short, long, default_value = "0")]
        flags: u32,
    },
    /// Delete mount point from umount list
    Del {
        /// mount point path
        mnt: String,
    },
    /// Wipe all entries from umount list
    Wipe,
}

#[derive(clap::Subcommand, Debug)]
enum Initrc {
    /// Regenerate preinit rc file
    Refresh,
}

fn emit_audit_dashboard_line(value: &serde_json::Value) -> Result<()> {
    println!("{}", serde_json::to_string(value)?);
    std::io::stdout().flush()?;
    Ok(())
}

fn stream_audit_dashboard() -> Result<()> {
    let root = std::path::Path::new(defs::MODULE_AUDIT_DIR);
    if crate::module_audit_log::dashboard_store_uninitialized(root)? {
        emit_audit_dashboard_line(&serde_json::json!({
            "type": "start",
            "total_modules": 0,
        }))?;
        return emit_audit_dashboard_line(&serde_json::json!({
            "type": "complete",
            "uninitialized": true,
            "store_revision": crate::module_audit_log::dashboard_store_revision(root)?,
        }));
    }

    crate::module_response::enforce_containment(false)?;
    let module_ids = crate::module_audit_log::dashboard_module_ids(root)?;
    emit_audit_dashboard_line(&serde_json::json!({
        "type": "start",
        "total_modules": module_ids.len(),
    }))?;

    let mut histories = Vec::with_capacity(module_ids.len());
    for (index, module_id) in module_ids.iter().enumerate() {
        match crate::module_audit_log::read_module_history_resilient(root, module_id, true) {
            std::result::Result::Ok(history) => {
                emit_audit_dashboard_line(&serde_json::json!({
                    "type": "module",
                    "module_id": module_id,
                    "completed": index + 1,
                    "total_modules": module_ids.len(),
                    "history": history,
                }))?;
                histories.push(history);
            }
            std::result::Result::Err(error) => {
                emit_audit_dashboard_line(&serde_json::json!({
                    "type": "error",
                    "phase": "verifying",
                    "module_id": module_id,
                    "completed": index,
                    "total_modules": module_ids.len(),
                    "error": format!("{error:#}"),
                }))?;
                return Err(error);
            }
        }
    }

    emit_audit_dashboard_line(&serde_json::json!({
        "type": "progress",
        "phase": "checkpoint",
        "completed": module_ids.len(),
        "total_modules": module_ids.len(),
    }))?;
    let checkpoint = crate::module_audit_log::checkpoint_payload(root)?;
    let checkpoint_revision = crate::module_audit_log::dashboard_store_revision(root)?;
    let checkpoint_heads = checkpoint
        .modules
        .iter()
        .map(|module| {
            (
                module.module_id.as_str(),
                (module.sequence, module.head_hash.as_str()),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    anyhow::ensure!(
        histories.len() == checkpoint_heads.len()
            && histories.iter().all(|history| {
                checkpoint_heads
                    .get(history.status.module_id.as_str())
                    .is_some_and(|(sequence, head_hash)| {
                        *sequence == u64::try_from(history.status.event_count).unwrap_or(u64::MAX)
                            && *head_hash == history.status.head_hash
                    })
            }),
        "audit inventory changed while the dashboard was being verified"
    );

    let stale = crate::module_audit_log::stale_histories_from_verified(
        &histories,
        std::path::Path::new(defs::MODULE_DIR),
        std::path::Path::new(defs::MODULE_UPDATE_DIR),
    );
    let seal_status = crate::module_audit_log::manager_audit_seal_status(root)?;
    let authorization_status = crate::module_audit_log::manager_audit_auth_status_for_inventory(
        root,
        &checkpoint.inventory_hash,
    )?;
    let store_revision = crate::module_audit_log::dashboard_store_revision(root)?;
    anyhow::ensure!(
        checkpoint_revision == store_revision,
        "audit store changed while the dashboard snapshot was being finalized"
    );
    emit_audit_dashboard_line(&serde_json::json!({
        "type": "complete",
        "checkpoint": checkpoint,
        "stale_histories": stale,
        "seal_status": seal_status,
        "authorization_status": authorization_status,
        "store_revision": store_revision,
    }))
}

fn watch_audit_dashboard(baseline: &str, timeout_seconds: u64) -> Result<()> {
    anyhow::ensure!(
        baseline.len() == 64 && baseline.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid audit dashboard revision"
    );
    anyhow::ensure!(timeout_seconds <= 60, "audit watch timeout is too large");
    let root = std::path::Path::new(defs::MODULE_AUDIT_DIR);
    let started = std::time::Instant::now();
    loop {
        let revision = crate::module_audit_log::dashboard_store_revision(root)?;
        if revision != baseline {
            return emit_audit_dashboard_line(&serde_json::json!({
                "type": "changed",
                "store_revision": revision,
            }));
        }
        if started.elapsed() >= std::time::Duration::from_secs(timeout_seconds) {
            return emit_audit_dashboard_line(&serde_json::json!({ "type": "timeout" }));
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

pub fn run() -> Result<()> {
    android_logger::init_once(
        Config::default()
            .with_max_level(crate::debug_select!(LevelFilter::Trace, LevelFilter::Info))
            .with_tag("KernelSU"),
    );

    // the kernel executes su with argv[0] = "su" and replace it with us
    let arg0 = std::env::args().next().unwrap_or_default();
    if arg0 == "su" || arg0 == "/system/bin/su" {
        return crate::su::root_shell();
    }

    if arg0.ends_with("resetprop") {
        let all_args: Vec<String> = std::env::args().collect();
        crate::resetprop::resetprop_main(&all_args)
    }

    let cli = Args::parse();

    log::info!("command: {:?}", cli.command);

    let result = match cli.command {
        Commands::PostFsData => init_event::on_post_data_fs(),
        Commands::BootCompleted => {
            init_event::on_boot_completed();
            Ok(())
        }

        Commands::SoftReboot => init_event::soft_reboot(),

        Commands::Insmod { module, params } => debug::insmod(&module, &params),

        Commands::Module { command } => {
            utils::switch_mnt_ns(1)?;
            match command {
                Module::Install { zip } => module::install_module(&zip),
                Module::Audit { zip, json } => crate::module_audit::print_zip_report(&zip, json),
                Module::AuditHistory { id, json } => {
                    let root = std::path::Path::new(crate::defs::MODULE_AUDIT_DIR);
                    let histories = if let Some(id) = id {
                        crate::module::validate_module_id(&id)?;
                        vec![crate::module_audit_log::read_module_history_resilient(
                            root, &id, true,
                        )?]
                    } else {
                        crate::module_audit_log::list_histories_resilient(root, true)?
                    };
                    if json {
                        println!("{}", serde_json::to_string_pretty(&histories)?);
                    } else {
                        for history in histories {
                            let status = history.status;
                            println!(
                                "{}: {:?}, events={}, high_risk={}, head={}",
                                status.module_id,
                                status.verification,
                                status.event_count,
                                status.high_risk,
                                status.head_hash
                            );
                        }
                    }
                    Ok(())
                }
                Module::AuditStatus { json } => {
                    let root = std::path::Path::new(crate::defs::MODULE_AUDIT_DIR);
                    crate::module_response::enforce_containment(false)?;
                    let statuses = crate::module_audit_log::list_modules_resilient(root, true)?;
                    if json {
                        println!("{}", serde_json::to_string_pretty(&statuses)?);
                    } else {
                        for status in statuses {
                            println!(
                                "{}: unresolved_risk={}, events={}",
                                status.module_id, status.unresolved_risk, status.event_count
                            );
                        }
                    }
                    Ok(())
                }
                Module::AuditDashboard => stream_audit_dashboard(),
                Module::AuditWatch {
                    baseline,
                    timeout_seconds,
                } => watch_audit_dashboard(&baseline, timeout_seconds),
                Module::AuditRecoveryStatus { json } => {
                    let status = crate::module_audit_log::sealed_integrity_status(
                        std::path::Path::new(crate::defs::MODULE_AUDIT_DIR),
                    )?;
                    if json {
                        println!("{}", serde_json::to_string_pretty(&status)?);
                    } else if status.failures.is_empty() {
                        println!("- Manager-sealed audit history is intact");
                    } else {
                        for failure in status.failures {
                            println!(
                                "{}: corrupted_from={}, {}",
                                failure.module_id, failure.corrupted_from_sequence, failure.reason
                            );
                        }
                    }
                    Ok(())
                }
                Module::AuditCheckpoint => {
                    let payload = crate::module_audit_log::checkpoint_payload(
                        std::path::Path::new(crate::defs::MODULE_AUDIT_DIR),
                    )?;
                    println!("{}", serde_json::to_string_pretty(&payload)?);
                    Ok(())
                }
                Module::AuditAuth { command } => {
                    let root = std::path::Path::new(crate::defs::MODULE_AUDIT_DIR);
                    match command {
                        AuditAuth::Status => {
                            let status = crate::module_audit_log::manager_audit_auth_status(root)?;
                            println!("{}", serde_json::to_string_pretty(&status)?);
                            Ok(())
                        }
                        AuditAuth::Register { public_key } => {
                            let status = crate::module_audit_log::register_manager_audit_auth_key(
                                root,
                                &public_key,
                                false,
                            )?;
                            println!("{}", serde_json::to_string_pretty(&status)?);
                            Ok(())
                        }
                        AuditAuth::Recover { public_key } => {
                            anyhow::ensure!(
                                ksucalls::try_check_kernel_safemode()
                                    .context("query KernelSU safe mode for Manager key recovery")?,
                                "Manager audit authorization recovery requires KernelSU safe mode"
                            );
                            let status = crate::module_audit_log::register_manager_audit_auth_key(
                                root,
                                &public_key,
                                true,
                            )?;
                            println!("{}", serde_json::to_string_pretty(&status)?);
                            Ok(())
                        }
                        AuditAuth::Challenge { action, id } => {
                            let arguments_hash = match action.as_str() {
                                "rescan" => {
                                    anyhow::ensure!(id.is_none(), "rescan does not accept --id");
                                    module::audit_rescan_arguments_hash()?
                                }
                                "prune" => module::audit_prune_arguments_hash(id.as_deref())?,
                                "secure-remove" => {
                                    let id = id
                                        .as_deref()
                                        .context("secure-remove authorization requires --id")?;
                                    crate::module_response::secure_remove_arguments_hash(id)?
                                }
                                "recover-sealed" => {
                                    let id = id
                                        .as_deref()
                                        .context("recover-sealed authorization requires --id")?;
                                    return crate::module_audit_log::manager_sealed_recovery_challenge(
                                        root, id,
                                    )
                                    .and_then(|challenge| {
                                        println!(
                                            "{}",
                                            serde_json::to_string_pretty(&challenge)?
                                        );
                                        Ok(())
                                    });
                                }
                                _ => anyhow::bail!("unsupported audit authorization action"),
                            };
                            let challenge = crate::module_audit_log::manager_audit_auth_challenge(
                                root,
                                &action,
                                &arguments_hash,
                            )?;
                            println!("{}", serde_json::to_string_pretty(&challenge)?);
                            Ok(())
                        }
                    }
                }
                Module::AuditSeal { command } => {
                    let root = std::path::Path::new(crate::defs::MODULE_AUDIT_DIR);
                    let status = match command {
                        AuditSeal::Status => {
                            crate::module_audit_log::manager_audit_seal_status(root)?
                        }
                        AuditSeal::Commit { file } => {
                            let metadata = std::fs::metadata(&file)?;
                            anyhow::ensure!(metadata.is_file(), "audit seal input is not a file");
                            anyhow::ensure!(
                                metadata.len() <= 16 * 1024 * 1024,
                                "audit seal input is too large"
                            );
                            let envelope = std::fs::read_to_string(file)?;
                            crate::module_audit_log::commit_manager_audit_seal(
                                root,
                                envelope.trim(),
                            )?
                        }
                    };
                    println!("{}", serde_json::to_string_pretty(&status)?);
                    Ok(())
                }
                Module::AuditRescan {
                    json,
                    authorization,
                } => module::audit_installed_modules(json, &authorization),
                Module::AuditPrune {
                    id,
                    dry_run,
                    json,
                    authorization,
                } => module::prune_module_audit_histories(
                    id.as_deref(),
                    dry_run,
                    json,
                    authorization.as_deref(),
                ),
                Module::AuditContain { id } => {
                    crate::module_response::contain_for_secure_removal(&id)
                }
                Module::AuditSecureRemove {
                    id,
                    json,
                    authorization,
                } => {
                    crate::module_response::secure_remove(&id, &authorization)?;
                    if json {
                        println!(
                            "{{\"module_id\":{},\"removed\":true}}",
                            serde_json::to_string(&id)?
                        );
                    } else {
                        println!("- Securely removed module {id}");
                    }
                    Ok(())
                }
                Module::AuditRecoverSealed {
                    id,
                    json,
                    authorization,
                } => {
                    let status =
                        crate::module_response::recover_manager_sealed_audit(&id, &authorization)?;
                    if json {
                        println!("{}", serde_json::to_string_pretty(&status)?);
                    } else {
                        println!("- Rebuilt Manager-sealed audit history for {id}");
                    }
                    Ok(())
                }
                Module::AuditResponseStatus => {
                    println!(
                        "{}",
                        serde_json::json!({
                            "kernel_safe_mode": ksucalls::try_check_kernel_safemode()
                                .context("query KernelSU safe mode for audit response")?,
                        })
                    );
                    Ok(())
                }
                Module::UndoUninstall { id } => module::undo_uninstall_module(&id),
                Module::Uninstall { id } => module::uninstall_module(&id),
                Module::Enable { id } => module::enable_module(&id),
                Module::Disable { id } => module::disable_module(&id),
                Module::Action { id } => module::run_action(&id),
                Module::List => module::list_modules(),
                Module::Config { internal, command } => {
                    let module_id = match internal {
                        Some(internal_name) => format!("internal.{internal_name}"),
                        None => std::env::var("KSU_MODULE").map_err(|_| {
                            anyhow::anyhow!(
                                "This command must be run in the context of a module or passed --internal <name>"
                            )
                        })?,
                    };
                    crate::module::validate_module_id(&module_id)?;

                    match command {
                        ModuleConfigCmd::Get { key } => {
                            // Use merge_configs to respect priority (temp overrides persist)
                            let config = module_config::merge_configs(&module_id)?;
                            match config.get(&key) {
                                Some(value) => {
                                    println!("{value}");
                                    Ok(())
                                }
                                None => anyhow::bail!("Key '{key}' not found"),
                            }
                        }
                        ModuleConfigCmd::Set {
                            key,
                            value,
                            stdin,
                            temp,
                        } => {
                            // Validate key at CLI layer for better user experience
                            module_config::validate_config_key(&key)?;

                            // Read value from stdin or argument
                            let value_str = match value {
                                Some(v) if !stdin => v,
                                _ => {
                                    // Read from stdin
                                    use std::io::Read;
                                    let mut buffer = String::new();
                                    std::io::stdin()
                                        .read_to_string(&mut buffer)
                                        .context("Failed to read from stdin")?;
                                    buffer
                                }
                            };

                            // Validate value
                            module_config::validate_config_value(&value_str)?;

                            let config_type = if temp {
                                module_config::ConfigType::Temp
                            } else {
                                module_config::ConfigType::Persist
                            };
                            module_config::set_config_value(
                                &module_id,
                                &key,
                                &value_str,
                                config_type,
                            )
                        }
                        ModuleConfigCmd::List => {
                            let config = module_config::merge_configs(&module_id)?;
                            if config.is_empty() {
                                println!("No config entries found");
                            } else {
                                for (key, value) in config {
                                    println!("{key}={value}");
                                }
                            }
                            Ok(())
                        }
                        ModuleConfigCmd::Delete { key, temp } => {
                            let config_type = if temp {
                                module_config::ConfigType::Temp
                            } else {
                                module_config::ConfigType::Persist
                            };
                            module_config::delete_config_value(&module_id, &key, config_type)
                        }
                        ModuleConfigCmd::Clear { temp } => {
                            let config_type = if temp {
                                module_config::ConfigType::Temp
                            } else {
                                module_config::ConfigType::Persist
                            };
                            module_config::clear_config(&module_id, config_type)
                        }
                    }
                }
            }
        }
        Commands::Install {
            libadbroot,
            data_path,
        } => utils::install(libadbroot, data_path),
        Commands::Unload => crate::unload::unload(),
        Commands::Uninstall { package_name } => utils::uninstall(&package_name),
        Commands::Sepolicy { command } => match command {
            Sepolicy::Patch { sepolicy } => crate::sepolicy::live_patch(&sepolicy),
            Sepolicy::Apply { file } => crate::sepolicy::apply_file(file),
            Sepolicy::Check { sepolicy } => crate::sepolicy::check_rule(&sepolicy),
        },
        Commands::LateLoad {
            magica,
            allow_shell,
            post_magica,
            kmi,
            package_name,
        } => {
            if let Some(port) = magica {
                return crate::magica::run(port, &package_name, allow_shell).map_err(|e| {
                    error!("Error running magica: {e}");
                    e
                });
            }
            let result = crate::late_load::run(&package_name, kmi, allow_shell);
            if post_magica {
                info!("Restoring adb properties (post-magica cleanup)...");
                if let Err(e) = crate::magica::disable_adb_root() {
                    error!("disable adb root failed: {e}");
                }
            }
            result
        }
        Commands::Services => {
            if ksucalls::get_version() <= 0 {
                info!("KernelSU not available, exiting services");
                std::process::exit(0);
            }
            init_event::on_services();
            Ok(())
        }
        Commands::Sulogd => sulog::run_sulogd(),
        Commands::Auditd => auditd::run_auditd(),
        Commands::AuditdRestartNotify => {
            auditd::record_restart_notify();
            Ok(())
        }
        Commands::Profile { command } => match command {
            Profile::GetSepolicy { package } => crate::profile::get_sepolicy(package),
            Profile::SetSepolicy { package, policy } => {
                crate::profile::set_sepolicy(package, policy)
            }
            Profile::GetTemplate { id } => crate::profile::get_template(id),
            Profile::SetTemplate { id, template } => crate::profile::set_template(id, template),
            Profile::DeleteTemplate { id } => crate::profile::delete_template(id),
            Profile::ListTemplates => crate::profile::list_templates(),
        },

        Commands::Feature { command } => match command {
            Feature::Get { id, config } => {
                if config {
                    crate::feature::get_feature_config(&id)
                } else {
                    crate::feature::get_feature(&id)
                }
            }
            Feature::Set { id, value } => crate::feature::set_feature(&id, value),
            Feature::List => {
                crate::feature::list_features();
                Ok(())
            }
            Feature::Check { id } => crate::feature::check_feature(&id),
            Feature::Load => crate::feature::load_config_and_apply(),
            Feature::Save => crate::feature::save_config(),
        },

        Commands::Debug { command } => match command {
            Debug::SetManager { apk } => debug::set_manager(&apk),
            Debug::GetSign { apk } => {
                let sign = apk_sign::get_apk_signature(&apk)?;
                println!("size: {:#x}, hash: {}", sign.0, sign.1);
                Ok(())
            }
            Debug::Version => {
                println!("Kernel Version: {}", ksucalls::get_version());
                Ok(())
            }
            Debug::Su { global_mnt } => crate::su::grant_root(global_mnt),
            Debug::Test => assets::ensure_binaries(false),
            Debug::ExtractBinary { name, path } => {
                let data = assets::get_asset_data(&name)?;
                utils::ensure_binary(&path, &data, false)
            }
            Debug::Mark { command } => match command {
                MarkCommand::Get { pid } => debug::mark_get(pid),
                MarkCommand::Mark { pid } => debug::mark_set(pid),
                MarkCommand::Unmark { pid } => debug::mark_unset(pid),
                MarkCommand::Refresh => debug::mark_refresh(),
            },
            Debug::Sulogd => sulog::ensure_sulogd_running(),
            Debug::Auditd => auditd::ensure_auditd_running(),
            Debug::Info => {
                let info = ksucalls::get_info();
                println!("version: {}", info.version);
                println!("flags: 0x{:x}", info.flags);
                println!("uapi_version: {}", info.uapi_version);
                println!("features: 0x{:x}", info.features);
                println!("lkm: {}", ksucalls::is_lkm());
                println!("late_load: {}", ksucalls::is_late_load());
                println!("runtime_mode: {}", ksucalls::runtime_mode());
                println!(
                    "pr_build: {}",
                    (info.flags & ksu_uapi::KSU_GET_INFO_FLAG_PR_BUILD) != 0
                );
                Ok(())
            }
            Debug::Package => {
                println!("{}", defs::DEFAULT_PACKAGE_NAME);
                Ok(())
            }
        },

        Commands::BootPatch(boot_patch) => crate::boot_patch::patch(boot_patch),

        Commands::BootInfo { command } => match command {
            BootInfo::CurrentKmi => {
                let kmi = crate::boot_patch::get_current_kmi()?;
                println!("{kmi}");
                // return here to avoid printing the error message
                return Ok(());
            }
            BootInfo::SupportedKmis => {
                let kmi = crate::assets::list_supported_kmi();
                for kmi in &kmi {
                    println!("{kmi}");
                }
                return Ok(());
            }
            BootInfo::IsAbDevice => {
                let val = crate::utils::getprop("ro.build.ab_update")
                    .unwrap_or_else(|| String::from("false"));
                let is_ab = val.trim().to_lowercase() == "true";
                println!("{}", if is_ab { "true" } else { "false" });
                return Ok(());
            }
            BootInfo::DefaultPartition => {
                let kmi = crate::boot_patch::get_current_kmi().unwrap_or_else(|_| String::new());
                let name = crate::boot_patch::choose_boot_partition(&kmi, false, &None);
                println!("{name}");
                return Ok(());
            }
            BootInfo::SlotSuffix { ota } => {
                let suffix = crate::boot_patch::get_slot_suffix(ota);
                println!("{suffix}");
                return Ok(());
            }
            BootInfo::AvailablePartitions => {
                let parts = crate::boot_patch::list_available_partitions();
                for p in &parts {
                    println!("{p}");
                }
                return Ok(());
            }
        },
        Commands::BootRestore(boot_restore) => crate::boot_patch::restore(boot_restore),
        Commands::BootPatchV2(patch) => crate::lkm_image::patch_boot(&patch),
        Commands::Resetprop { args } => {
            let mut full_args = vec!["resetprop".to_string()];
            full_args.extend(args);
            crate::resetprop::resetprop_main(&full_args)
        }

        Commands::Kernel { command } => match command {
            Kernel::NukeExt4Sysfs { mnt } => ksucalls::nuke_ext4_sysfs(&mnt),
            Kernel::Umount { command } => match command {
                UmountOp::Add { mnt, flags } => ksucalls::umount_list_add(&mnt, flags),
                UmountOp::Del { mnt } => ksucalls::umount_list_del(&mnt),
                UmountOp::Wipe => ksucalls::umount_list_wipe().map_err(Into::into),
            },
            Kernel::NotifyModuleMounted => {
                ksucalls::report_module_mounted();
                Ok(())
            }
        },
        Commands::Initrc { command } => match command {
            Initrc::Refresh => regenerate_preinit_rc(),
        },
    };

    if let Err(e) = &result {
        log::error!("Error: {e:?}");
    }
    result
}
