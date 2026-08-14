use crate::{defs, ksucalls, metamodule, module, module_audit_log};
use anyhow::{Context, Result, bail, ensure};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

const PERSISTENT_SCRIPT_DIRS: &[&str] = &[
    "/data/adb/post-fs-data.d",
    "/data/adb/service.d",
    "/data/adb/boot-completed.d",
    "/data/adb/bootcompleted.d",
];

const AUDIT_EMERGENCY_SCHEMA_VERSION: u32 = 1;
const AUDIT_STATE_UNAVAILABLE_ERROR: &str = "audit_state_unavailable";
const AUDIT_MODULE_CONTAINED_ERROR: &str = "audit_module_contained";

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditEmergencyPhase {
    Applying,
    Contained,
    Incomplete,
    Recovered,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditEmergencyReason {
    AuditStateUnavailable,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditEmergencyRecoveryCondition {
    ManagerSealedInventoryVerified,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct AuditEmergencyStatus {
    pub schema_version: u32,
    pub active: bool,
    pub phase: AuditEmergencyPhase,
    pub reason: AuditEmergencyReason,
    pub detail: String,
    pub affected_module_ids: Vec<String>,
    pub script_quarantine_root: String,
    pub containment_failures: Vec<String>,
    pub recovery_condition: AuditEmergencyRecoveryCondition,
    pub triggered_at_unix_seconds: u64,
    pub updated_at_unix_seconds: u64,
}

#[derive(Debug)]
pub struct ContainmentOutcome {
    pub module_ids: Vec<String>,
    pub audit_unavailable: bool,
    pub audit_error: Option<String>,
}

pub fn audit_emergency_status() -> Result<Option<AuditEmergencyStatus>> {
    read_audit_emergency_status(Path::new(defs::AUDIT_EMERGENCY_STATUS_FILE))
}

fn read_audit_emergency_status(path: &Path) -> Result<Option<AuditEmergencyStatus>> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("read audit emergency status {}", path.display()));
        }
    };
    let status: AuditEmergencyStatus = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse audit emergency status {}", path.display()))?;
    ensure!(
        status.schema_version == AUDIT_EMERGENCY_SCHEMA_VERSION,
        "unsupported audit emergency status schema {}",
        status.schema_version
    );
    Ok(Some(status))
}

fn write_audit_emergency_status(path: &Path, status: &AuditEmergencyStatus) -> Result<()> {
    let parent = path
        .parent()
        .context("audit emergency status path has no parent")?;
    ensure_private_dir(parent)?;
    let mut bytes = serde_json::to_vec_pretty(status)?;
    bytes.push(b'\n');
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temporary = parent.join(format!(".status-{}-{unique}.tmp", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .context("create temporary audit emergency status")?;
    file.write_all(&bytes)
        .context("write temporary audit emergency status")?;
    file.sync_all()
        .context("sync temporary audit emergency status")?;
    std::fs::rename(&temporary, path).context("commit audit emergency status")?;
    sync_directory(parent)
}

fn unix_time_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn best_effort_module_ids(module_roots: &[&Path]) -> Vec<String> {
    let mut ids = BTreeSet::new();
    for root in module_roots {
        let Ok(entries) = std::fs::read_dir(root) else {
            continue;
        };
        for entry in entries.flatten() {
            if entry.path().is_dir() {
                ids.insert(entry.file_name().to_string_lossy().into_owned());
            }
        }
    }
    ids.into_iter().collect()
}

fn persist_active_emergency_status(
    path: &Path,
    phase: AuditEmergencyPhase,
    detail: &str,
    affected_module_ids: Vec<String>,
    script_quarantine_root: &Path,
    containment_failures: Vec<String>,
) -> Result<()> {
    let now = unix_time_seconds();
    let triggered_at = match read_audit_emergency_status(path) {
        Ok(Some(status)) if status.active => status.triggered_at_unix_seconds,
        Ok(_) => now,
        Err(error) => {
            warn!("cannot preserve previous audit emergency timestamp: {error:#}");
            now
        }
    };
    write_audit_emergency_status(
        path,
        &AuditEmergencyStatus {
            schema_version: AUDIT_EMERGENCY_SCHEMA_VERSION,
            active: true,
            phase,
            reason: AuditEmergencyReason::AuditStateUnavailable,
            detail: detail.to_owned(),
            affected_module_ids,
            script_quarantine_root: script_quarantine_root.to_string_lossy().into_owned(),
            containment_failures,
            recovery_condition: AuditEmergencyRecoveryCondition::ManagerSealedInventoryVerified,
            triggered_at_unix_seconds: triggered_at,
            updated_at_unix_seconds: now,
        },
    )
}

fn mark_audit_emergency_recovered(path: &Path) -> Result<()> {
    let Some(mut status) = read_audit_emergency_status(path)? else {
        return Ok(());
    };
    if !status.active {
        return Ok(());
    }
    status.active = false;
    status.phase = AuditEmergencyPhase::Recovered;
    status.updated_at_unix_seconds = unix_time_seconds();
    write_audit_emergency_status(path, &status)
}

/// Reject ordinary module mutations while authenticated audit state requires
/// incident response. The audit store remains authoritative; callers must not
/// infer safety from mutable module marker files.
pub fn ensure_action_allowed(id: &str, action: &str) -> Result<()> {
    ensure!(
        !module_audit_log::module_requires_secure_removal(Path::new(defs::MODULE_AUDIT_DIR), id,)?,
        "Module {id} has an unresolved audit integrity incident; cannot {action}. Use Security & Audit Center"
    );
    Ok(())
}

pub fn active_containment_ids() -> Result<BTreeSet<String>> {
    trusted_containment_ids(
        Path::new(defs::MODULE_AUDIT_DIR),
        &[
            Path::new(defs::MODULE_DIR),
            Path::new(defs::MODULE_UPDATE_DIR),
        ],
    )
}

/// Verify the complete Manager-sealed inventory before allowing a module to
/// become active. The caller must hold the audit coordinator until activation
/// has been materialized, so the verified inventory cannot change in between.
pub fn ensure_activation_allowed(id: &str) -> Result<()> {
    module::validate_module_id(id)?;
    let outcome = enforce_containment(false).with_context(|| {
        format!(
            "[{AUDIT_STATE_UNAVAILABLE_ERROR}] cannot verify module audit state before enabling {id}"
        )
    })?;
    ensure_activation_outcome_allowed(id, &outcome)
}

fn ensure_activation_outcome_allowed(id: &str, outcome: &ContainmentOutcome) -> Result<()> {
    ensure!(
        !outcome.audit_unavailable,
        "[{AUDIT_STATE_UNAVAILABLE_ERROR}] module audit state is unavailable; cannot enable {id}: {}",
        outcome.audit_error.as_deref().unwrap_or("unknown error")
    );
    ensure!(
        !outcome.module_ids.iter().any(|module_id| module_id == id),
        "[{AUDIT_MODULE_CONTAINED_ERROR}] module {id} is contained by verified audit state; cannot enable it"
    );
    Ok(())
}

/// Cancel a conventional uninstall marker before untrusted module code can run.
/// Returns true when incident response consumed the pending uninstall.
pub fn intercept_unsafe_normal_uninstall(module_path: &Path) -> Result<bool> {
    let module_id = module_path
        .file_name()
        .and_then(|name| name.to_str())
        .context("module path has no valid module id")?;
    if !module_audit_log::module_requires_secure_removal(
        Path::new(defs::MODULE_AUDIT_DIR),
        module_id,
    )? {
        return Ok(false);
    }
    crate::utils::ensure_file_exists(module_path.join(defs::DISABLE_FILE_NAME))?;
    let remove = module_path.join(defs::REMOVE_FILE_NAME);
    if remove.exists() {
        std::fs::remove_file(&remove)
            .with_context(|| format!("cancel unsafe uninstall for module '{module_id}'"))?;
    }
    warn!(
        "refusing normal uninstall scripts for untrusted module {module_id}; use Security & Audit Center"
    );
    Ok(true)
}

pub fn contain_for_secure_removal(id: &str) -> Result<()> {
    module::validate_module_id(id)?;
    ensure!(
        module_audit_log::module_requires_containment(Path::new(defs::MODULE_AUDIT_DIR), id)?,
        "Module {id} does not require secure removal"
    );
    let mut found = false;
    for root in [defs::MODULE_DIR, defs::MODULE_UPDATE_DIR] {
        let module_path = Path::new(root).join(id);
        if !module_path.exists() {
            continue;
        }
        found = true;
        crate::utils::ensure_file_exists(module_path.join(defs::DISABLE_FILE_NAME))?;
        let remove_path = module_path.join(defs::REMOVE_FILE_NAME);
        if remove_path.exists() {
            std::fs::remove_file(&remove_path)
                .with_context(|| format!("cancel unsafe normal uninstall for module '{id}'"))?;
        }
    }
    ensure!(found, "Module {id} content not found");
    module_audit_log::set_containment_state(
        Path::new(defs::MODULE_AUDIT_DIR),
        id,
        module_audit_log::ContainmentState::PendingReboot,
    )?;
    module::regenerate_preinit_rc()?;
    info!("Module {id} contained for KernelSU safe-mode removal");
    Ok(())
}

/// Materialize authenticated audit containment into KernelSU's conventional
/// module-disable markers. The audit state remains authoritative, so deleting a
/// marker cannot make the module active again.
pub fn enforce_containment(boot_enforcement: bool) -> Result<ContainmentOutcome> {
    let audit_root = Path::new(defs::MODULE_AUDIT_DIR);
    let emergency_status_path = Path::new(defs::AUDIT_EMERGENCY_STATUS_FILE);
    let emergency_root = Path::new(defs::AUDIT_EMERGENCY_DIR);
    let module_roots = [
        Path::new(defs::MODULE_DIR),
        Path::new(defs::MODULE_UPDATE_DIR),
    ];
    let ids = match trusted_containment_ids(audit_root, &module_roots) {
        Ok(ids) => ids,
        Err(error) => {
            let reason = format!("{error:#}");
            warn!(
                "module audit state is unavailable; applying emergency fail-closed containment: {reason}"
            );
            let discovered_ids = best_effort_module_ids(&module_roots);
            if let Err(status_error) = persist_active_emergency_status(
                emergency_status_path,
                AuditEmergencyPhase::Applying,
                &reason,
                discovered_ids.clone(),
                emergency_root,
                Vec::new(),
            ) {
                warn!("failed to record applying audit emergency state: {status_error:#}");
            }
            let response = enforce_fail_closed(
                &module_roots,
                &PERSISTENT_SCRIPT_DIRS
                    .iter()
                    .map(|path| Path::new(*path))
                    .collect::<Vec<_>>(),
                emergency_root,
                module::regenerate_preinit_rc,
            );
            return match response {
                Ok(ids) => {
                    let module_ids = ids.into_iter().collect::<Vec<_>>();
                    persist_active_emergency_status(
                        emergency_status_path,
                        AuditEmergencyPhase::Contained,
                        &reason,
                        module_ids.clone(),
                        emergency_root,
                        Vec::new(),
                    )?;
                    Ok(ContainmentOutcome {
                        module_ids,
                        audit_unavailable: true,
                        audit_error: Some(reason),
                    })
                }
                Err(containment_error) => {
                    let failure = format!("{containment_error:#}");
                    if let Err(status_error) = persist_active_emergency_status(
                        emergency_status_path,
                        AuditEmergencyPhase::Incomplete,
                        &reason,
                        discovered_ids,
                        emergency_root,
                        vec![failure.clone()],
                    ) {
                        bail!(
                            "{failure}; persist incomplete audit emergency status: {status_error:#}"
                        );
                    }
                    Err(containment_error)
                }
            };
        }
    };

    // Exclude the module first. Auxiliary persistent-script quarantine must not
    // weaken the primary response if a malicious filesystem object makes an
    // individual move fail.
    let mut changed = false;
    for id in &ids {
        module_audit_log::set_containment_state(
            audit_root,
            id,
            module_audit_log::ContainmentState::PendingReboot,
        )?;
        for root in [defs::MODULE_DIR, defs::MODULE_UPDATE_DIR] {
            let module_path = Path::new(root).join(id);
            if !module_path.is_dir() {
                continue;
            }
            let disable = module_path.join(defs::DISABLE_FILE_NAME);
            if !disable.exists() {
                crate::utils::ensure_file_exists(&disable)?;
                changed = true;
            }
            let remove = module_path.join(defs::REMOVE_FILE_NAME);
            if remove.exists() {
                std::fs::remove_file(&remove)
                    .with_context(|| format!("cancel unsafe uninstall for module '{id}'"))?;
                changed = true;
            }
        }
    }
    if changed {
        module::regenerate_preinit_rc()?;
    }

    let persistent_results = quarantine_persistent_scripts(audit_root, &ids);
    let may_complete = boot_enforcement || ksucalls::try_check_kernel_safemode().unwrap_or(false);
    for id in &ids {
        let result = persistent_results.get(id);
        let failures = result.map_or(&[][..], |result| result.failures.as_slice());
        if !failures.is_empty() {
            warn!(
                "persistent startup script containment for {id} is incomplete: {}",
                failures.join("; ")
            );
            module_audit_log::set_containment_state(
                audit_root,
                id,
                module_audit_log::ContainmentState::PersistentScriptsIncomplete,
            )?;
        } else if may_complete {
            module_audit_log::set_containment_state(
                audit_root,
                id,
                module_audit_log::ContainmentState::Contained,
            )?;
        }
    }

    mark_audit_emergency_recovered(emergency_status_path)?;
    Ok(ContainmentOutcome {
        module_ids: ids.into_iter().collect(),
        audit_unavailable: false,
        audit_error: None,
    })
}

fn trusted_containment_ids(audit_root: &Path, module_roots: &[&Path]) -> Result<BTreeSet<String>> {
    let revision_before = module_audit_log::dashboard_store_revision(audit_root)
        .context("read module audit revision before containment verification")?;
    let sealed = module_audit_log::sealed_integrity_status(audit_root)
        .context("verify Manager-sealed module audit inventory")?;
    let statuses = module_audit_log::list_modules_resilient(audit_root, false)
        .context("verify current module audit histories")?;
    let revision_after = module_audit_log::dashboard_store_revision(audit_root)
        .context("read module audit revision after containment verification")?;
    ensure!(
        revision_before == revision_after,
        "module audit store changed during containment verification"
    );

    let mut audited = BTreeSet::new();
    let mut contained = sealed
        .failures
        .into_iter()
        .map(|failure| failure.module_id)
        .collect::<BTreeSet<_>>();
    for status in statuses {
        ensure!(
            status.manager_checkpoint == module_audit_log::CheckpointState::Sealed,
            "module {} has no Manager-sealed audit history",
            status.module_id
        );
        if status.unresolved_risk || status.containment_state.is_some() {
            contained.insert(status.module_id.clone());
        }
        audited.insert(status.module_id);
    }

    for (module_id, _) in managed_module_paths(module_roots)? {
        module::validate_module_id(&module_id)
            .with_context(|| format!("invalid installed or pending module id {module_id:?}"))?;
        ensure!(
            audited.contains(&module_id),
            "installed or pending module {module_id} has no verified audit history"
        );
    }
    Ok(contained)
}

fn managed_module_paths(module_roots: &[&Path]) -> Result<Vec<(String, PathBuf)>> {
    let mut modules = Vec::new();
    for root in module_roots {
        let entries = match std::fs::read_dir(root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).with_context(|| format!("read module root {}", root.display()));
            }
        };
        for entry in entries {
            let entry = entry?;
            if !entry.path().is_dir() {
                continue;
            }
            modules.push((
                entry.file_name().to_string_lossy().into_owned(),
                entry.path(),
            ));
        }
    }
    modules.sort_by(|left, right| left.1.cmp(&right.1));
    Ok(modules)
}

fn enforce_fail_closed(
    module_roots: &[&Path],
    persistent_dirs: &[&Path],
    quarantine_root: &Path,
    regenerate_preinit_rc: impl FnOnce() -> Result<()>,
) -> Result<BTreeSet<String>> {
    let mut errors = Vec::new();
    let mut ids = BTreeSet::new();
    for root in module_roots {
        let entries = match std::fs::read_dir(root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                errors.push(format!(
                    "read fail-closed module root {}: {error:#}",
                    root.display()
                ));
                continue;
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    errors.push(format!(
                        "read fail-closed module entry in {}: {error:#}",
                        root.display()
                    ));
                    continue;
                }
            };
            let module_path = entry.path();
            if !module_path.is_dir() {
                continue;
            }
            ids.insert(entry.file_name().to_string_lossy().into_owned());
            if let Err(error) =
                ensure_fail_closed_disable(&module_path.join(defs::DISABLE_FILE_NAME))
            {
                errors.push(format!(
                    "disable fail-closed module {}: {error:#}",
                    module_path.display()
                ));
            }
            let remove = module_path.join(defs::REMOVE_FILE_NAME);
            match std::fs::symlink_metadata(&remove) {
                Ok(_) => {
                    if let Err(error) = std::fs::remove_file(&remove) {
                        errors.push(format!(
                            "remove untrusted uninstall marker {}: {error:#}",
                            remove.display()
                        ));
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => errors.push(format!(
                    "inspect untrusted uninstall marker {}: {error:#}",
                    remove.display()
                )),
            }
        }
    }

    match quarantine_all_persistent_scripts(persistent_dirs, quarantine_root) {
        Ok(paths) if !paths.is_empty() => warn!(
            "quarantined {} persistent startup entries because module audit state is unavailable",
            paths.len()
        ),
        Ok(_) => {}
        Err(error) => errors.push(format!(
            "quarantine persistent startup entries without trusted ownership: {error:#}"
        )),
    }

    if let Err(error) = regenerate_preinit_rc() {
        errors.push(format!("regenerate fail-closed modules.rc: {error:#}"));
    }
    if !errors.is_empty() {
        bail!(errors.join("; "));
    }
    Ok(ids)
}

fn ensure_fail_closed_disable(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(()),
        Ok(metadata) if metadata.file_type().is_symlink() => {
            std::fs::remove_file(path)
                .with_context(|| format!("remove symlinked disable marker {}", path.display()))?;
            crate::utils::ensure_file_exists(path)
        }
        Ok(_) => bail!("{} is not a regular disable marker", path.display()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            crate::utils::ensure_file_exists(path)
        }
        Err(error) => {
            Err(error).with_context(|| format!("inspect disable marker {}", path.display()))
        }
    }
}

fn quarantine_all_persistent_scripts(
    source_dirs: &[&Path],
    quarantine_root: &Path,
) -> Result<Vec<PathBuf>> {
    let mut pending = Vec::<(usize, PathBuf, OsString)>::new();
    for (index, source_dir) in source_dirs.iter().enumerate() {
        let entries = match std::fs::read_dir(source_dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("read persistent startup directory {}", source_dir.display())
                });
            }
        };
        for entry in entries {
            let entry = entry?;
            pending.push((index, entry.path(), entry.file_name()));
        }
    }
    if pending.is_empty() {
        return Ok(Vec::new());
    }

    let session = create_emergency_quarantine_session(quarantine_root)?;
    let mut moved = Vec::new();
    let mut errors = Vec::new();
    let mut destination_dirs = BTreeSet::new();
    for (index, source, name) in pending {
        let destination_dir = session.join(index.to_string());
        if let Err(error) = ensure_private_dir(&destination_dir) {
            errors.push(format!(
                "prepare emergency quarantine for {}: {error:#}",
                source.display()
            ));
            continue;
        }
        destination_dirs.insert(destination_dir.clone());
        let destination = destination_dir.join(name);
        match std::fs::rename(&source, &destination) {
            Ok(()) => moved.push(source),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => errors.push(format!(
                "move {} into emergency quarantine: {error:#}",
                source.display()
            )),
        }
    }
    for destination_dir in destination_dirs {
        sync_directory(&destination_dir)?;
    }
    sync_directory(&session)?;
    for source_dir in source_dirs {
        if source_dir.is_dir() {
            sync_directory(source_dir)?;
        }
    }
    if !errors.is_empty() {
        bail!(errors.join("; "));
    }
    Ok(moved)
}

fn create_emergency_quarantine_session(root: &Path) -> Result<PathBuf> {
    ensure_private_dir(root)?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    for counter in 0_u32..1024 {
        let session = root.join(format!(
            "persistent-{timestamp}-{}-{counter}",
            std::process::id()
        ));
        match std::fs::create_dir(&session) {
            Ok(()) => {
                set_private_permissions(&session)?;
                sync_directory(root)?;
                return Ok(session);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error).context("create emergency quarantine session"),
        }
    }
    bail!("cannot allocate a unique emergency quarantine session")
}

fn ensure_private_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)
        .with_context(|| format!("create private directory {}", path.display()))?;
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspect private directory {}", path.display()))?;
    ensure!(
        metadata.file_type().is_dir(),
        "{} is not a real directory",
        path.display()
    );
    set_private_permissions(path)
}

fn set_private_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("set private permissions on {}", path.display()))?;
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    std::fs::File::open(path)
        .with_context(|| format!("open directory {} for sync", path.display()))?
        .sync_all()
        .with_context(|| format!("sync directory {}", path.display()))
}

/// Apply the last known containment set when the authenticated audit root is
/// unavailable. This is only a best-effort runtime stopgap; the persisted audit
/// store and Manager seal remain the authority once they are visible again.
pub fn enforce_memory_containment(ids: &BTreeSet<String>) -> Result<Vec<String>> {
    let mut changed = false;
    for id in ids {
        if let Err(error) = module::validate_module_id(id) {
            warn!("skip invalid in-memory containment module id '{id}': {error:#}");
            continue;
        }

        for root in [defs::MODULE_DIR, defs::MODULE_UPDATE_DIR] {
            let module_path = Path::new(root).join(id);
            if !module_path.is_dir() {
                continue;
            }

            let disable = module_path.join(defs::DISABLE_FILE_NAME);
            if !disable.exists() {
                crate::utils::ensure_file_exists(&disable)?;
                changed = true;
            }

            let remove = module_path.join(defs::REMOVE_FILE_NAME);
            if remove.exists() {
                std::fs::remove_file(&remove)
                    .with_context(|| format!("cancel unsafe uninstall for module '{id}'"))?;
                changed = true;
            }
        }
    }

    if changed {
        module::regenerate_preinit_rc()?;
    }

    Ok(ids.iter().cloned().collect())
}

#[derive(Default)]
struct PersistentContainmentResult {
    uncertain_ownership: bool,
    quarantined_paths: Vec<String>,
    failures: Vec<String>,
}

fn quarantine_persistent_scripts(
    audit_root: &Path,
    affected_ids: &BTreeSet<String>,
) -> BTreeMap<String, PersistentContainmentResult> {
    // Use only Manager-sealed evidence. Exact ownership is preferred. If a
    // damaged module has no surviving event, preserve paths attributed by every
    // other intact history and quarantine the remainder as uncertain ownership.
    let mut results = BTreeMap::new();
    let mut plans = match module_audit_log::persistent_script_containment_plans(audit_root) {
        Ok(plans) => plans,
        Err(error) => {
            let reason = format!("build trusted persistent-script plan: {error:#}");
            for id in affected_ids {
                results
                    .entry(id.clone())
                    .or_insert_with(PersistentContainmentResult::default)
                    .failures
                    .push(reason.clone());
            }
            persist_containment_results(audit_root, &mut results);
            return results;
        }
    };
    plans.sort_by(|left, right| left.module_id.cmp(&right.module_id));
    for plan in plans.iter().filter(|plan| !plan.paths.is_empty()) {
        let result = results.entry(plan.module_id.clone()).or_default();
        match module_audit_log::quarantine_persistent_scripts(
            audit_root,
            &plan.module_id,
            &plan.paths,
            false,
        ) {
            Ok(outcome) => {
                result.quarantined_paths = outcome.completed_paths;
                result.failures.extend(outcome.failures);
            }
            Err(error) => result
                .failures
                .push(format!("quarantine attributed startup scripts: {error:#}")),
        }
    }
    let inference_ids = plans
        .iter()
        .filter(|plan| plan.infer_unattributed)
        .map(|plan| plan.module_id.clone())
        .collect::<Vec<_>>();
    if !inference_ids.is_empty() {
        let inference = (|| -> Result<module_audit_log::PersistentScriptQuarantineOutcome> {
            let trusted = module_audit_log::trusted_persistent_script_paths(audit_root)?
                .into_iter()
                .collect::<BTreeSet<_>>();
            let unknown =
                collect_unattributed_persistent_scripts(PERSISTENT_SCRIPT_DIRS, &trusted)?;
            if unknown.is_empty() {
                return Ok(module_audit_log::PersistentScriptQuarantineOutcome::default());
            }
            warn!(
                "{} damaged audit histories have no trusted persistent-script inventory; quarantining {} globally unattributed startup scripts",
                inference_ids.len(),
                unknown.len()
            );
            module_audit_log::quarantine_unattributed_persistent_scripts(audit_root, &unknown)
        })();
        for id in inference_ids {
            let result = results.entry(id).or_default();
            result.uncertain_ownership = true;
            match &inference {
                Ok(outcome) => {
                    result
                        .quarantined_paths
                        .clone_from(&outcome.completed_paths);
                    result.failures.extend(outcome.failures.clone());
                }
                Err(error) => result.failures.push(format!(
                    "quarantine unattributed startup scripts: {error:#}"
                )),
            }
        }
    }
    persist_containment_results(audit_root, &mut results);
    results
}

fn persist_containment_results(
    audit_root: &Path,
    results: &mut BTreeMap<String, PersistentContainmentResult>,
) {
    for (id, result) in results.iter_mut() {
        if let Err(error) = module_audit_log::record_persistent_containment_result(
            audit_root,
            id,
            result.uncertain_ownership,
            &result.quarantined_paths,
            &result.failures,
        ) {
            result.failures.push(format!(
                "authenticate persistent containment result: {error:#}"
            ));
        }
    }
}

fn collect_unattributed_persistent_scripts(
    directories: &[&str],
    trusted: &BTreeSet<String>,
) -> Result<Vec<String>> {
    let mut unknown = Vec::new();
    for directory in directories {
        let directory = Path::new(directory);
        if !directory.is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path().to_string_lossy().into_owned();
            if !trusted.contains(&path) {
                unknown.push(path);
            }
        }
    }
    unknown.sort();
    Ok(unknown)
}

pub fn secure_remove_arguments_hash(module_id: &str) -> Result<String> {
    module::validate_module_id(module_id)?;
    let targets = secure_remove_targets(module_id)?;
    module_audit_log::manager_operation_arguments_hash("secure-remove", &targets)
}

fn secure_remove_targets(module_id: &str) -> Result<Vec<String>> {
    let audit_root = Path::new(defs::MODULE_AUDIT_DIR);
    if let Some(targets) =
        module_audit_log::active_manager_audit_operation_targets(audit_root, "secure-remove")?
    {
        ensure!(
            targets == [module_id],
            "requested module does not match the active secure removal operation"
        );
        return Ok(targets);
    }
    ensure!(
        module_audit_log::module_requires_secure_removal(audit_root, module_id)?,
        "Module {module_id} does not have an unresolved audit integrity incident"
    );
    Ok(vec![module_id.to_owned()])
}

pub fn secure_remove(module_id: &str, authorization: &str) -> Result<()> {
    module::validate_module_id(module_id)?;
    ensure!(
        ksucalls::try_check_kernel_safemode()
            .context("query KernelSU safe mode for secure removal")?,
        "Secure module removal requires KernelSU safe mode"
    );
    let targets = secure_remove_targets(module_id)?;
    let arguments_hash =
        module_audit_log::manager_operation_arguments_hash("secure-remove", &targets)?;
    let audit_root = Path::new(defs::MODULE_AUDIT_DIR);
    let operation = module_audit_log::begin_manager_audit_operation(
        audit_root,
        authorization,
        "secure-remove",
        &arguments_hash,
        &targets,
    )?;
    if operation.applied {
        return Ok(());
    }

    let metamodule_link = Path::new(defs::METAMODULE_DIR.trim_end_matches('/'));
    let was_metamodule = metamodule::get_metamodule_id().as_deref() == Some(module_id)
        || std::fs::read_link(metamodule_link).is_ok_and(|target| {
            target.file_name().and_then(|name| name.to_str()) == Some(module_id)
        });
    let removed_paths = module_audit_log::quarantine_module_for_secure_removal(
        audit_root,
        Path::new(defs::MODULE_DIR),
        Path::new(defs::MODULE_UPDATE_DIR),
        &operation.operation_id,
        module_id,
    )?;
    if was_metamodule {
        metamodule::remove_symlink().context("remove quarantined metamodule symlink")?;
    }
    crate::module_config::clear_module_configs(module_id)
        .context("clear securely removed module configuration")?;
    module::regenerate_preinit_rc()?;
    module_audit_log::complete_secure_module_removal(
        audit_root,
        &operation.operation_id,
        module_id,
        removed_paths,
    )?;
    module_audit_log::finish_manager_audit_operation(audit_root, &operation.operation_id)
}

pub fn recover_manager_sealed_audit(
    module_id: &str,
    authorization: &str,
) -> Result<module_audit_log::ModuleAuditStatus> {
    module::validate_module_id(module_id)?;
    ensure!(
        ksucalls::try_check_kernel_safemode()
            .context("query KernelSU safe mode for Manager-sealed audit recovery")?,
        "Manager-sealed audit recovery requires KernelSU safe mode"
    );
    module_audit_log::recover_manager_sealed_module(
        Path::new(defs::MODULE_AUDIT_DIR),
        module_id,
        authorization,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn quarantined_entry_count(root: &Path) -> usize {
        let mut count = 0;
        let mut pending = vec![root.to_path_buf()];
        while let Some(directory) = pending.pop() {
            let Ok(entries) = std::fs::read_dir(directory) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    pending.push(path);
                } else {
                    count += 1;
                }
            }
        }
        count
    }

    #[test]
    fn emergency_status_tracks_containment_and_verified_recovery() {
        let temp = tempfile::tempdir().unwrap();
        let emergency_root = temp.path().join("audit-emergency");
        let status_path = emergency_root.join("status.json");

        persist_active_emergency_status(
            &status_path,
            AuditEmergencyPhase::Applying,
            "audit root is missing",
            vec!["module.alpha".into()],
            &emergency_root,
            Vec::new(),
        )
        .unwrap();
        let applying = read_audit_emergency_status(&status_path).unwrap().unwrap();
        assert!(applying.active);
        assert_eq!(applying.phase, AuditEmergencyPhase::Applying);
        assert_eq!(applying.affected_module_ids, ["module.alpha"]);

        persist_active_emergency_status(
            &status_path,
            AuditEmergencyPhase::Contained,
            "audit root is missing",
            vec!["module.alpha".into(), "module.beta".into()],
            &emergency_root,
            Vec::new(),
        )
        .unwrap();
        let contained = read_audit_emergency_status(&status_path).unwrap().unwrap();
        assert!(contained.active);
        assert_eq!(contained.phase, AuditEmergencyPhase::Contained);
        assert_eq!(
            contained.triggered_at_unix_seconds,
            applying.triggered_at_unix_seconds
        );

        mark_audit_emergency_recovered(&status_path).unwrap();
        let recovered = read_audit_emergency_status(&status_path).unwrap().unwrap();
        assert!(!recovered.active);
        assert_eq!(recovered.phase, AuditEmergencyPhase::Recovered);
        assert_eq!(
            recovered.recovery_condition,
            AuditEmergencyRecoveryCondition::ManagerSealedInventoryVerified
        );
    }

    #[test]
    fn unavailable_audit_state_rejects_module_activation() {
        let outcome = ContainmentOutcome {
            module_ids: Vec::new(),
            audit_unavailable: true,
            audit_error: Some("module audit root is missing".into()),
        };

        let error = ensure_activation_outcome_allowed("module.alpha", &outcome).unwrap_err();
        assert!(format!("{error:#}").contains(AUDIT_STATE_UNAVAILABLE_ERROR));
    }

    #[test]
    fn verified_containment_rejects_only_affected_module_activation() {
        let outcome = ContainmentOutcome {
            module_ids: vec!["module.alpha".into()],
            audit_unavailable: false,
            audit_error: None,
        };

        let error = ensure_activation_outcome_allowed("module.alpha", &outcome).unwrap_err();
        assert!(format!("{error:#}").contains(AUDIT_MODULE_CONTAINED_ERROR));
        ensure_activation_outcome_allowed("module.beta", &outcome).unwrap();
    }

    #[test]
    fn unavailable_audit_state_disables_every_module_and_quarantines_startup_entries() {
        let temp = tempfile::tempdir().unwrap();
        let installed = temp.path().join("modules");
        let pending = temp.path().join("modules_update");
        let post_fs_data = temp.path().join("post-fs-data.d");
        let service = temp.path().join("service.d");
        let quarantine = temp.path().join("audit-emergency");
        for path in [&installed, &pending, &post_fs_data, &service] {
            std::fs::create_dir_all(path).unwrap();
        }
        let installed_module = installed.join("installed.module");
        let pending_module = pending.join("pending.module");
        std::fs::create_dir(&installed_module).unwrap();
        std::fs::create_dir(&pending_module).unwrap();
        std::fs::write(installed_module.join(defs::REMOVE_FILE_NAME), b"").unwrap();
        std::fs::write(post_fs_data.join("early.sh"), b"#!/system/bin/sh\n").unwrap();
        std::fs::write(service.join("late.sh"), b"#!/system/bin/sh\n").unwrap();

        let regenerated = Cell::new(false);
        let ids = enforce_fail_closed(
            &[&installed, &pending],
            &[&post_fs_data, &service],
            &quarantine,
            || {
                regenerated.set(true);
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(
            ids,
            BTreeSet::from(["installed.module".into(), "pending.module".into()])
        );
        assert!(installed_module.join(defs::DISABLE_FILE_NAME).is_file());
        assert!(pending_module.join(defs::DISABLE_FILE_NAME).is_file());
        assert!(!installed_module.join(defs::REMOVE_FILE_NAME).exists());
        assert_eq!(std::fs::read_dir(&post_fs_data).unwrap().count(), 0);
        assert_eq!(std::fs::read_dir(&service).unwrap().count(), 0);
        assert_eq!(quarantined_entry_count(&quarantine), 2);
        assert!(regenerated.get());
    }

    #[test]
    fn fail_closed_attempts_every_response_before_returning_an_error() {
        let temp = tempfile::tempdir().unwrap();
        let modules = temp.path().join("modules");
        let persistent = temp.path().join("service.d");
        let quarantine = temp.path().join("audit-emergency");
        let module_path = modules.join("broken.module");
        std::fs::create_dir_all(module_path.join(defs::DISABLE_FILE_NAME)).unwrap();
        std::fs::create_dir_all(&persistent).unwrap();
        std::fs::write(persistent.join("payload.sh"), b"#!/system/bin/sh\n").unwrap();

        let regenerated = Cell::new(false);
        let error = enforce_fail_closed(&[&modules], &[&persistent], &quarantine, || {
            regenerated.set(true);
            Ok(())
        })
        .unwrap_err();

        assert!(format!("{error:#}").contains("disable fail-closed module"));
        assert_eq!(std::fs::read_dir(&persistent).unwrap().count(), 0);
        assert_eq!(quarantined_entry_count(&quarantine), 1);
        assert!(regenerated.get());
    }
}
