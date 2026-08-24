use crate::{
    defs, ksucalls, metamodule, module,
    module_audit_action::AuditAction,
    module_audit_assessment::{self, AssessedAuditSnapshot, AuditAssessmentContext},
    module_audit_log,
    module_audit_transaction::{self, AuditTransaction, AuditTransactionReceipt},
};
use anyhow::{Context, Result, bail, ensure};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
const PERSISTENT_INITRC_DIR: &str = "/data/adb/initrc.d";

const AUDIT_EMERGENCY_SCHEMA_VERSION: u32 = 1;
const SCRIPT_QUARANTINE_MANIFEST_SCHEMA_VERSION: u32 = 2;
const SCRIPT_QUARANTINE_MANIFEST_FILE: &str = "manifest.json";
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

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditEmergencyScriptQuarantineState {
    Planned,
    Moved,
    Failed,
    Deleted,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct AuditEmergencyScriptQuarantineEntry {
    #[serde(default)]
    pub entry_id: String,
    #[serde(
        default,
        skip_serializing_if = "module_audit_log::AuditIncidentCause::is_unknown"
    )]
    pub cause: module_audit_log::AuditIncidentCause,
    pub source_path: String,
    pub quarantine_path: String,
    pub state: AuditEmergencyScriptQuarantineState,
    #[serde(default, skip_serializing_if = "is_false")]
    pub delete_requested: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recovery_routes: Vec<module_audit_log::AuditRecoveryRoute>,
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn script_quarantine_entry_id(session: &Path, source: &Path, quarantine: &Path) -> String {
    let bytes = serde_json::to_vec(&(
        "emergency-script-quarantine",
        session.to_string_lossy(),
        source.to_string_lossy(),
        quarantine.to_string_lossy(),
    ))
    .unwrap_or_default();
    format!("{:x}", Sha256::digest(bytes))
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct AuditEmergencyScriptQuarantineManifest {
    pub schema_version: u32,
    pub session_path: String,
    pub entries: Vec<AuditEmergencyScriptQuarantineEntry>,
    pub created_at_unix_seconds: u64,
    pub updated_at_unix_seconds: u64,
}

#[derive(Debug, Default)]
struct ScriptQuarantineManifestCollection {
    manifests: Vec<AuditEmergencyScriptQuarantineManifest>,
    failures: Vec<String>,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub script_quarantines: Vec<AuditEmergencyScriptQuarantineManifest>,
    pub containment_failures: Vec<String>,
    pub recovery_condition: AuditEmergencyRecoveryCondition,
    pub triggered_at_unix_seconds: u64,
    pub updated_at_unix_seconds: u64,
}

#[derive(Debug)]
pub struct ContainmentOutcome {
    pub module_ids: Vec<String>,
    pub audit_state: AuditStateAvailability,
    pub audit_error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditStateAvailability {
    Verified,
    CleanUninitialized,
    Unavailable,
}

pub fn audit_emergency_status() -> Result<Option<AuditEmergencyStatus>> {
    let Some(mut status) =
        read_audit_emergency_status(Path::new(defs::AUDIT_EMERGENCY_STATUS_FILE))?
    else {
        return Ok(None);
    };
    let quarantine_root = Path::new(&status.script_quarantine_root);
    let assessment = current_audit_assessment().ok();
    let audit_state_verified = assessment
        .as_ref()
        .is_some_and(|value| value.assessment.ensure_complete_inventory().is_ok());
    let authorization_configured = assessment
        .as_ref()
        .is_some_and(|value| value.assessment.authorization_configured);
    match read_script_quarantine_manifests(quarantine_root) {
        Ok(mut collection) => {
            apply_script_quarantine_routes(
                &mut collection.manifests,
                audit_state_verified,
                authorization_configured,
            );
            status.script_quarantines = collection.manifests;
            status.containment_failures.extend(collection.failures);
        }
        Err(error) => status.containment_failures.push(format!(
            "read persistent startup script quarantine manifests: {error:#}"
        )),
    }
    Ok(Some(status))
}

pub fn quarantined_script_delete_arguments_hash(entry_id: &str) -> Result<String> {
    ensure!(
        entry_id.len() == 64 && entry_id.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid quarantined script entry id"
    );
    let collection = read_script_quarantine_manifests(Path::new(defs::AUDIT_EMERGENCY_DIR))?;
    ensure!(
        collection.failures.is_empty(),
        "cannot authorize deletion while quarantine manifests are unreadable: {}",
        collection.failures.join("; ")
    );
    let matches = collection
        .manifests
        .iter()
        .flat_map(|manifest| manifest.entries.iter().map(move |entry| (manifest, entry)))
        .filter(|(_, entry)| entry.entry_id == entry_id)
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1,
        "quarantined script entry is unavailable"
    );
    let (manifest, entry) = matches[0];
    ensure!(
        matches!(
            entry.state,
            AuditEmergencyScriptQuarantineState::Moved
                | AuditEmergencyScriptQuarantineState::Deleted
        ),
        "quarantined script entry is not ready for deletion"
    );
    ensure_quarantined_script_route_ready(entry_id, AuditAction::DeleteQuarantinedScript)?;
    let bytes = serde_json::to_vec(&(
        AuditAction::DeleteQuarantinedScript,
        entry_id,
        &manifest.session_path,
        &entry.source_path,
        &entry.quarantine_path,
    ))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

pub fn delete_quarantined_script(
    entry_id: &str,
    authorization: &str,
) -> Result<AuditTransactionReceipt> {
    let arguments_hash = quarantined_script_delete_arguments_hash(entry_id)?;
    let targets = vec![entry_id.to_owned()];
    let audit_root = Path::new(defs::MODULE_AUDIT_DIR);
    let mut transaction = AuditTransaction::begin(
        audit_root,
        authorization,
        AuditAction::DeleteQuarantinedScript,
        &arguments_hash,
        &targets,
    )?;
    if transaction.is_committed() {
        return transaction.commit();
    }

    let collection = read_script_quarantine_manifests(Path::new(defs::AUDIT_EMERGENCY_DIR))?;
    ensure!(
        collection.failures.is_empty(),
        "cannot delete while quarantine manifests are unreadable: {}",
        collection.failures.join("; ")
    );
    let mut selected = collection
        .manifests
        .into_iter()
        .filter(|manifest| {
            manifest
                .entries
                .iter()
                .any(|entry| entry.entry_id == entry_id)
        })
        .collect::<Vec<_>>();
    ensure!(
        selected.len() == 1,
        "quarantined script entry is unavailable"
    );
    let mut manifest = selected.remove(0);
    let entry_index = manifest
        .entries
        .iter()
        .position(|entry| entry.entry_id == entry_id)
        .context("quarantined script entry disappeared")?;
    let session = PathBuf::from(&manifest.session_path);
    let quarantine = PathBuf::from(&manifest.entries[entry_index].quarantine_path);
    ensure!(
        quarantine.starts_with(&session),
        "quarantined script path escapes its session"
    );
    ensure!(
        std::fs::symlink_metadata(&manifest.entries[entry_index].source_path)
            .is_err_and(|error| error.kind() == io::ErrorKind::NotFound),
        "refusing deletion while the startup source path exists"
    );
    manifest.schema_version = SCRIPT_QUARANTINE_MANIFEST_SCHEMA_VERSION;
    manifest.entries[entry_index].delete_requested = true;
    manifest.updated_at_unix_seconds = unix_time_seconds();
    write_script_quarantine_manifest(&session, &manifest)?;

    match std::fs::symlink_metadata(&quarantine) {
        Ok(metadata) => {
            ensure!(
                metadata.file_type().is_file(),
                "refusing to delete a non-regular quarantined startup entry"
            );
            std::fs::remove_file(&quarantine)
                .with_context(|| format!("delete quarantined script {}", quarantine.display()))?;
            sync_directory(
                quarantine
                    .parent()
                    .context("quarantined script has no parent")?,
            )?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("inspect quarantined script before deletion"),
    }
    manifest.entries[entry_index].state = AuditEmergencyScriptQuarantineState::Deleted;
    manifest.entries[entry_index].error = None;
    manifest.entries[entry_index].recovery_routes.clear();
    manifest.updated_at_unix_seconds = unix_time_seconds();
    write_script_quarantine_manifest(&session, &manifest)?;
    transaction.complete_target(entry_id)?;
    transaction.commit()
}

pub fn quarantined_script_retry_arguments_hash(entry_id: &str) -> Result<String> {
    let collection = read_script_quarantine_manifests(Path::new(defs::AUDIT_EMERGENCY_DIR))?;
    ensure!(
        collection.failures.is_empty(),
        "quarantine manifests are unreadable"
    );
    let matches = collection
        .manifests
        .iter()
        .flat_map(|manifest| manifest.entries.iter().map(move |entry| (manifest, entry)))
        .filter(|(_, entry)| entry.entry_id == entry_id)
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1,
        "quarantined script entry is unavailable"
    );
    let (manifest, entry) = matches[0];
    ensure!(
        matches!(
            entry.state,
            AuditEmergencyScriptQuarantineState::Planned
                | AuditEmergencyScriptQuarantineState::Failed
                | AuditEmergencyScriptQuarantineState::Moved
        ),
        "quarantined script entry cannot be retried"
    );
    ensure_quarantined_script_route_ready(entry_id, AuditAction::RetryScriptContainment)?;
    let bytes = serde_json::to_vec(&(
        AuditAction::RetryScriptContainment,
        entry_id,
        &manifest.session_path,
        &entry.source_path,
        &entry.quarantine_path,
    ))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn ensure_quarantined_script_route_ready(entry_id: &str, action: AuditAction) -> Result<()> {
    let status = audit_emergency_status()?.context("audit emergency status is unavailable")?;
    let route = status
        .script_quarantines
        .iter()
        .flat_map(|manifest| manifest.entries.iter())
        .find(|entry| entry.entry_id == entry_id)
        .and_then(|entry| {
            entry
                .recovery_routes
                .iter()
                .find(|route| route.action == action.route_name())
        })
        .context("quarantined script recovery route is unavailable")?;
    ensure!(
        route.ready,
        "quarantined script recovery conditions are not satisfied"
    );
    Ok(())
}

pub fn retry_quarantined_script_containment(
    entry_id: &str,
    authorization: &str,
) -> Result<AuditTransactionReceipt> {
    let arguments_hash = quarantined_script_retry_arguments_hash(entry_id)?;
    let targets = vec![entry_id.to_owned()];
    let audit_root = Path::new(defs::MODULE_AUDIT_DIR);
    let mut transaction = AuditTransaction::begin(
        audit_root,
        authorization,
        AuditAction::RetryScriptContainment,
        &arguments_hash,
        &targets,
    )?;
    if transaction.is_committed() {
        return transaction.commit();
    }
    let collection = read_script_quarantine_manifests(Path::new(defs::AUDIT_EMERGENCY_DIR))?;
    ensure!(
        collection.failures.is_empty(),
        "quarantine manifests are unreadable"
    );
    let mut selected = collection
        .manifests
        .into_iter()
        .filter(|manifest| {
            manifest
                .entries
                .iter()
                .any(|entry| entry.entry_id == entry_id)
        })
        .collect::<Vec<_>>();
    ensure!(
        selected.len() == 1,
        "quarantined script entry is unavailable"
    );
    let mut manifest = selected.remove(0);
    let entry_index = manifest
        .entries
        .iter()
        .position(|entry| entry.entry_id == entry_id)
        .context("quarantined script entry disappeared")?;
    let session = PathBuf::from(&manifest.session_path);
    let source = PathBuf::from(&manifest.entries[entry_index].source_path);
    let quarantine = PathBuf::from(&manifest.entries[entry_index].quarantine_path);
    validate_script_quarantine_entry(&session, &manifest.entries[entry_index])?;
    let source_missing = std::fs::symlink_metadata(&source)
        .is_err_and(|error| error.kind() == io::ErrorKind::NotFound);
    let quarantine_metadata = std::fs::symlink_metadata(&quarantine);
    if source_missing
        && quarantine_metadata
            .as_ref()
            .is_ok_and(|metadata| metadata.file_type().is_file())
    {
        manifest.entries[entry_index].state = AuditEmergencyScriptQuarantineState::Moved;
    } else {
        let metadata = std::fs::symlink_metadata(&source)
            .context("inspect persistent script before containment retry")?;
        ensure!(
            metadata.file_type().is_file(),
            "refusing to quarantine a non-regular startup entry"
        );
        ensure!(
            quarantine_metadata.is_err_and(|error| error.kind() == io::ErrorKind::NotFound),
            "quarantine destination already exists"
        );
        ensure_private_dir(
            quarantine
                .parent()
                .context("quarantine destination has no parent")?,
        )?;
        std::fs::rename(&source, &quarantine)
            .context("retry persistent startup script containment")?;
        sync_directory(source.parent().context("startup source has no parent")?)?;
        sync_directory(
            quarantine
                .parent()
                .context("quarantine destination has no parent")?,
        )?;
        manifest.entries[entry_index].state = AuditEmergencyScriptQuarantineState::Moved;
    }
    manifest.schema_version = SCRIPT_QUARANTINE_MANIFEST_SCHEMA_VERSION;
    manifest.entries[entry_index].error = None;
    manifest.entries[entry_index].recovery_routes.clear();
    manifest.updated_at_unix_seconds = unix_time_seconds();
    write_script_quarantine_manifest(&session, &manifest)?;
    transaction.complete_target(entry_id)?;
    transaction.commit()
}

pub(crate) fn quarantined_script_action_completed(
    entry_id: &str,
    action: AuditAction,
) -> Result<bool> {
    let collection = read_script_quarantine_manifests(Path::new(defs::AUDIT_EMERGENCY_DIR))?;
    ensure!(
        collection.failures.is_empty(),
        "quarantine manifests are unreadable"
    );
    let mut manifests = collection
        .manifests
        .into_iter()
        .filter(|manifest| {
            manifest
                .entries
                .iter()
                .any(|entry| entry.entry_id == entry_id)
        })
        .collect::<Vec<_>>();
    ensure!(
        manifests.len() == 1,
        "quarantined script entry is unavailable"
    );
    let mut manifest = manifests.remove(0);
    let entry_index = manifest
        .entries
        .iter()
        .position(|entry| entry.entry_id == entry_id)
        .context("quarantined script entry disappeared")?;
    let session = PathBuf::from(&manifest.session_path);
    validate_script_quarantine_entry(&session, &manifest.entries[entry_index])?;
    let source = PathBuf::from(&manifest.entries[entry_index].source_path);
    let quarantine = PathBuf::from(&manifest.entries[entry_index].quarantine_path);
    match action {
        AuditAction::DeleteQuarantinedScript => {
            if manifest.entries[entry_index].state == AuditEmergencyScriptQuarantineState::Deleted {
                return Ok(true);
            }
            ensure!(
                std::fs::symlink_metadata(&source)
                    .is_err_and(|error| error.kind() == io::ErrorKind::NotFound),
                "refusing deletion while the startup source path exists"
            );
            manifest.schema_version = SCRIPT_QUARANTINE_MANIFEST_SCHEMA_VERSION;
            manifest.entries[entry_index].delete_requested = true;
            manifest.updated_at_unix_seconds = unix_time_seconds();
            write_script_quarantine_manifest(&session, &manifest)?;
            match std::fs::symlink_metadata(&quarantine) {
                Ok(metadata) => {
                    ensure!(
                        metadata.file_type().is_file(),
                        "refusing to delete a non-regular quarantined startup entry"
                    );
                    std::fs::remove_file(&quarantine)?;
                    sync_directory(
                        quarantine
                            .parent()
                            .context("quarantined script has no parent")?,
                    )?;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error).context("resume quarantined script deletion"),
            }
            manifest.entries[entry_index].state = AuditEmergencyScriptQuarantineState::Deleted;
            manifest.entries[entry_index].error = None;
            manifest.entries[entry_index].recovery_routes.clear();
        }
        AuditAction::RetryScriptContainment => {
            if manifest.entries[entry_index].state == AuditEmergencyScriptQuarantineState::Moved {
                return Ok(true);
            }
            let metadata = std::fs::symlink_metadata(&source)
                .context("inspect startup entry while resuming containment")?;
            ensure!(
                metadata.file_type().is_file(),
                "refusing to quarantine a non-regular startup entry"
            );
            ensure!(
                std::fs::symlink_metadata(&quarantine)
                    .is_err_and(|error| error.kind() == io::ErrorKind::NotFound),
                "quarantine destination already exists"
            );
            ensure_private_dir(
                quarantine
                    .parent()
                    .context("quarantine destination has no parent")?,
            )?;
            std::fs::rename(&source, &quarantine)?;
            sync_directory(source.parent().context("startup source has no parent")?)?;
            sync_directory(
                quarantine
                    .parent()
                    .context("quarantine destination has no parent")?,
            )?;
            manifest.schema_version = SCRIPT_QUARANTINE_MANIFEST_SCHEMA_VERSION;
            manifest.entries[entry_index].state = AuditEmergencyScriptQuarantineState::Moved;
            manifest.entries[entry_index].error = None;
            manifest.entries[entry_index].recovery_routes.clear();
        }
        _ => bail!("audit action does not operate on quarantined scripts"),
    }
    manifest.updated_at_unix_seconds = unix_time_seconds();
    write_script_quarantine_manifest(&session, &manifest)?;
    Ok(true)
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

fn directory_has_entries(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => return Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(error).with_context(|| format!("inspect directory {}", path.display()));
        }
    }
    let mut entries = match std::fs::read_dir(path) {
        Ok(entries) => entries,
        Err(error) => {
            return Err(error).with_context(|| format!("read directory {}", path.display()));
        }
    };
    match entries.next() {
        Some(Ok(_)) => Ok(true),
        Some(Err(error)) => Err(error).with_context(|| format!("read entry in {}", path.display())),
        None => Ok(false),
    }
}

fn clean_uninitialized_audit_state(
    audit_root: &Path,
    module_roots: &[&Path],
    persistent_script_dirs: &[&Path],
    persistent_initrc_dir: &Path,
    metamodule_path: &Path,
) -> Result<bool> {
    match std::fs::symlink_metadata(audit_root) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => return Ok(false),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect audit root {}", audit_root.display()));
        }
    }
    if !module_audit_log::dashboard_store_uninitialized(audit_root)? {
        return Ok(false);
    }
    for path in module_roots
        .iter()
        .chain(persistent_script_dirs)
        .copied()
        .chain(std::iter::once(persistent_initrc_dir))
    {
        if directory_has_entries(path)? {
            return Ok(false);
        }
    }
    match std::fs::symlink_metadata(metamodule_path) {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error)
            .with_context(|| format!("inspect metamodule path {}", metamodule_path.display())),
    }
}

fn discard_empty_emergency_status(path: &Path, quarantine_root: &Path) -> Result<()> {
    let Some(status) = read_audit_emergency_status(path)? else {
        return Ok(());
    };
    if !status.active
        || !status.affected_module_ids.is_empty()
        || !status.script_quarantines.is_empty()
        || !status.containment_failures.is_empty()
    {
        return Ok(());
    }
    let manifests = read_script_quarantine_manifests(quarantine_root)?;
    if !manifests.manifests.is_empty() || !manifests.failures.is_empty() {
        return Ok(());
    }
    for entry in std::fs::read_dir(quarantine_root)
        .context("inspect payload-free audit emergency directory")?
    {
        if entry?.path() != path {
            return Ok(());
        }
    }
    std::fs::remove_file(path).context("remove payload-free audit emergency status")?;
    sync_directory(
        path.parent()
            .context("audit emergency status path has no parent")?,
    )
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
            script_quarantines: Vec::new(),
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
    let assessed = current_audit_assessment()?;
    ensure!(
        !assessed
            .assessment
            .module(id)
            .is_some_and(|module| module.disposition.requires_secure_removal()),
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
        outcome.audit_state == AuditStateAvailability::Verified,
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
    let assessed = current_audit_assessment()?;
    if !assessed
        .assessment
        .module(module_id)
        .is_some_and(|module| module.disposition.requires_secure_removal())
    {
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
    let assessed = current_audit_assessment()?;
    ensure!(
        assessed
            .assessment
            .module(id)
            .is_some_and(|module| module.disposition.requires_containment()),
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
    let persistent_script_dirs = PERSISTENT_SCRIPT_DIRS
        .iter()
        .map(|path| Path::new(*path))
        .collect::<Vec<_>>();
    let clean_uninitialized = clean_uninitialized_audit_state(
        audit_root,
        &module_roots,
        &persistent_script_dirs,
        Path::new(PERSISTENT_INITRC_DIR),
        Path::new(defs::METAMODULE_DIR.trim_end_matches('/')),
    );
    match clean_uninitialized {
        Ok(true) => {
            if let Err(error) =
                discard_empty_emergency_status(emergency_status_path, emergency_root)
            {
                warn!("failed to discard empty audit emergency status: {error:#}");
            }
            return Ok(ContainmentOutcome {
                module_ids: Vec::new(),
                audit_state: AuditStateAvailability::CleanUninitialized,
                audit_error: Some("module audit state is not initialized".to_owned()),
            });
        }
        Ok(false) => {}
        Err(error) => warn!(
            "cannot prove that the uninitialized audit state is payload-free; applying fail-closed containment: {error:#}"
        ),
    }
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
                &persistent_script_dirs,
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
                        audit_state: AuditStateAvailability::Unavailable,
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
        audit_state: AuditStateAvailability::Verified,
        audit_error: None,
    })
}

fn trusted_containment_ids(audit_root: &Path, module_roots: &[&Path]) -> Result<BTreeSet<String>> {
    let assessed = current_audit_assessment_for(audit_root, module_roots)
        .context("assess current module audit inventory")?;
    assessed.assessment.ensure_complete_inventory()?;
    Ok(assessed.assessment.containment_module_ids())
}

pub(crate) fn current_audit_assessment() -> Result<AssessedAuditSnapshot> {
    current_audit_assessment_for(
        Path::new(defs::MODULE_AUDIT_DIR),
        &[
            Path::new(defs::MODULE_DIR),
            Path::new(defs::MODULE_UPDATE_DIR),
        ],
    )
}

pub(crate) fn assess_current_audit_snapshot(
    snapshot: module_audit_log::VerifiedAuditSnapshot,
) -> Result<AssessedAuditSnapshot> {
    assess_audit_snapshot_for(
        snapshot,
        &[
            Path::new(defs::MODULE_DIR),
            Path::new(defs::MODULE_UPDATE_DIR),
        ],
    )
}

fn current_audit_assessment_for(
    audit_root: &Path,
    module_roots: &[&Path],
) -> Result<AssessedAuditSnapshot> {
    let context = audit_assessment_context(module_roots)?;
    let snapshot = module_audit_log::verified_audit_snapshot(audit_root)?;
    Ok(module_audit_assessment::assess_verified_snapshot(
        snapshot, &context,
    ))
}

fn assess_audit_snapshot_for(
    snapshot: module_audit_log::VerifiedAuditSnapshot,
    module_roots: &[&Path],
) -> Result<AssessedAuditSnapshot> {
    let context = audit_assessment_context(module_roots)?;
    Ok(module_audit_assessment::assess_verified_snapshot(
        snapshot, &context,
    ))
}

fn audit_assessment_context(module_roots: &[&Path]) -> Result<AuditAssessmentContext> {
    let module_content_ids = managed_module_paths(module_roots)?
        .into_iter()
        .map(|(module_id, _)| {
            module::validate_module_id(&module_id)
                .with_context(|| format!("invalid installed or pending module id {module_id:?}"))?;
            Ok(module_id)
        })
        .collect::<Result<BTreeSet<_>>>()?;
    Ok(AuditAssessmentContext {
        kernel_safe_mode: ksucalls::try_check_kernel_safemode().unwrap_or(false),
        module_content_ids,
    })
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
    let now = unix_time_seconds();
    let mut manifest = AuditEmergencyScriptQuarantineManifest {
        schema_version: SCRIPT_QUARANTINE_MANIFEST_SCHEMA_VERSION,
        session_path: session.to_string_lossy().into_owned(),
        entries: pending
            .iter()
            .map(
                |(index, source, name)| AuditEmergencyScriptQuarantineEntry {
                    entry_id: script_quarantine_entry_id(
                        &session,
                        source,
                        &session.join(index.to_string()).join(name),
                    ),
                    cause: module_audit_log::AuditIncidentCause::Unknown,
                    source_path: source.to_string_lossy().into_owned(),
                    quarantine_path: session
                        .join(index.to_string())
                        .join(name)
                        .to_string_lossy()
                        .into_owned(),
                    state: AuditEmergencyScriptQuarantineState::Planned,
                    delete_requested: false,
                    error: None,
                    recovery_routes: Vec::new(),
                },
            )
            .collect(),
        created_at_unix_seconds: now,
        updated_at_unix_seconds: now,
    };
    // Commit the complete source-to-destination plan before moving anything.
    // After a crash, the manifest remains sufficient to locate either copy.
    write_script_quarantine_manifest(&session, &manifest)?;
    let mut moved = Vec::new();
    let mut errors = Vec::new();
    for (entry_index, (index, source, name)) in pending.into_iter().enumerate() {
        let destination_dir = session.join(index.to_string());
        if let Err(error) = ensure_private_dir(&destination_dir) {
            let failure = format!(
                "prepare emergency quarantine for {}: {error:#}",
                source.display()
            );
            manifest.entries[entry_index].state = AuditEmergencyScriptQuarantineState::Failed;
            manifest.entries[entry_index].error = Some(failure.clone());
            manifest.updated_at_unix_seconds = unix_time_seconds();
            write_script_quarantine_manifest(&session, &manifest)?;
            errors.push(failure);
            continue;
        }
        let destination = destination_dir.join(name);
        let move_result = (|| -> Result<()> {
            std::fs::rename(&source, &destination)
                .with_context(|| format!("move {} into emergency quarantine", source.display()))?;
            sync_directory(&destination_dir)?;
            if let Some(source_dir) = source.parent() {
                sync_directory(source_dir)?;
            }
            Ok(())
        })();
        match move_result {
            Ok(()) => {
                moved.push(source);
                manifest.entries[entry_index].state = AuditEmergencyScriptQuarantineState::Moved;
                manifest.entries[entry_index].error = None;
            }
            Err(error) => {
                let failure = format!("{error:#}");
                manifest.entries[entry_index].state = AuditEmergencyScriptQuarantineState::Failed;
                manifest.entries[entry_index].error = Some(failure.clone());
                errors.push(failure);
            }
        }
        manifest.updated_at_unix_seconds = unix_time_seconds();
        write_script_quarantine_manifest(&session, &manifest)?;
    }
    if !errors.is_empty() {
        bail!(errors.join("; "));
    }
    Ok(moved)
}

fn write_script_quarantine_manifest(
    session: &Path,
    manifest: &AuditEmergencyScriptQuarantineManifest,
) -> Result<()> {
    let path = session.join(SCRIPT_QUARANTINE_MANIFEST_FILE);
    let mut bytes = serde_json::to_vec_pretty(manifest)?;
    bytes.push(b'\n');
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temporary = session.join(format!(
        ".{SCRIPT_QUARANTINE_MANIFEST_FILE}-{}-{unique}.tmp",
        std::process::id()
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .context("create temporary emergency script quarantine manifest")?;
    file.write_all(&bytes)
        .context("write emergency script quarantine manifest")?;
    file.sync_all()
        .context("sync emergency script quarantine manifest")?;
    std::fs::rename(&temporary, &path).context("commit emergency script quarantine manifest")?;
    sync_directory(session)
}

fn validate_script_quarantine_entry(
    session: &Path,
    entry: &AuditEmergencyScriptQuarantineEntry,
) -> Result<()> {
    let source = Path::new(&entry.source_path);
    let quarantine = Path::new(&entry.quarantine_path);
    #[cfg(not(test))]
    let source_parent = source.parent().context("startup source has no parent")?;
    let source_name = source
        .file_name()
        .context("startup source has no file name")?;
    let relative = quarantine
        .strip_prefix(session)
        .context("quarantine path escapes its session")?;
    let components = relative.components().collect::<Vec<_>>();
    let encoded_index = components
        .first()
        .and_then(|component| component.as_os_str().to_str())
        .and_then(|value| value.parse::<usize>().ok())
        .context("quarantine path has no valid source directory index")?;
    #[cfg(not(test))]
    let source_index = PERSISTENT_SCRIPT_DIRS
        .iter()
        .position(|candidate| source_parent == Path::new(candidate))
        .context("startup source is outside an approved persistent directory")?;
    #[cfg(test)]
    let source_index = encoded_index;
    ensure!(
        components.len() == 2
            && encoded_index == source_index
            && components[1].as_os_str() == source_name,
        "quarantine path does not match its approved startup source"
    );
    let expected_id = script_quarantine_entry_id(session, source, quarantine);
    ensure!(
        entry.entry_id.is_empty() || entry.entry_id == expected_id,
        "quarantine entry id mismatch"
    );
    Ok(())
}

fn read_script_quarantine_manifests(root: &Path) -> Result<ScriptQuarantineManifestCollection> {
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(ScriptQuarantineManifestCollection::default());
        }
        Err(error) => return Err(error).context("read emergency script quarantine root"),
    };
    let mut collection = ScriptQuarantineManifestCollection::default();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                collection.failures.push(format!(
                    "read emergency script quarantine session: {error:#}"
                ));
                continue;
            }
        };
        let session = entry.path();
        let is_directory = match entry.file_type() {
            Ok(file_type) => file_type.is_dir(),
            Err(error) => {
                collection.failures.push(format!(
                    "inspect emergency script quarantine session {}: {error:#}",
                    session.display()
                ));
                continue;
            }
        };
        if !is_directory
            || !entry
                .file_name()
                .to_string_lossy()
                .starts_with("persistent-")
        {
            continue;
        }
        let path = session.join(SCRIPT_QUARANTINE_MANIFEST_FILE);
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                collection.failures.push(format!(
                    "inspect script quarantine manifest {}: {error:#}",
                    path.display()
                ));
                continue;
            }
        };
        let loaded = (|| -> Result<AuditEmergencyScriptQuarantineManifest> {
            ensure!(
                metadata.file_type().is_file(),
                "script quarantine manifest is not a regular file"
            );
            ensure!(
                metadata.len() <= 1024 * 1024,
                "script quarantine manifest is too large"
            );
            let bytes = std::fs::read(&path).context("read script quarantine manifest")?;
            let mut manifest: AuditEmergencyScriptQuarantineManifest =
                serde_json::from_slice(&bytes).context("parse script quarantine manifest")?;
            ensure!(
                matches!(
                    manifest.schema_version,
                    1 | SCRIPT_QUARANTINE_MANIFEST_SCHEMA_VERSION
                ),
                "unsupported script quarantine manifest schema {}",
                manifest.schema_version
            );
            ensure!(
                Path::new(&manifest.session_path) == session,
                "script quarantine manifest session path mismatch"
            );
            for entry in &manifest.entries {
                validate_script_quarantine_entry(&session, entry)?;
            }
            reconcile_script_quarantine_manifest(&mut manifest);
            Ok(manifest)
        })();
        match loaded {
            Ok(manifest) => collection.manifests.push(manifest),
            Err(error) => {
                collection.failures.push(format!(
                    "read script quarantine manifest {}: {error:#}",
                    path.display()
                ));
            }
        }
    }
    collection
        .manifests
        .sort_by(|left, right| left.session_path.cmp(&right.session_path));
    Ok(collection)
}

fn reconcile_script_quarantine_manifest(manifest: &mut AuditEmergencyScriptQuarantineManifest) {
    let session_path = manifest.session_path.clone();
    for entry in &mut manifest.entries {
        if entry.entry_id.is_empty() {
            entry.entry_id = script_quarantine_entry_id(
                Path::new(&session_path),
                Path::new(&entry.source_path),
                Path::new(&entry.quarantine_path),
            );
        }
        let source_exists = std::fs::symlink_metadata(&entry.source_path).is_ok();
        let quarantine_exists = std::fs::symlink_metadata(&entry.quarantine_path).is_ok();
        if entry.delete_requested && !source_exists && !quarantine_exists {
            entry.state = AuditEmergencyScriptQuarantineState::Deleted;
            entry.error = None;
            entry.recovery_routes.clear();
            continue;
        }
        match (source_exists, quarantine_exists) {
            (false, true) => {
                entry.state = AuditEmergencyScriptQuarantineState::Moved;
                entry.cause = module_audit_log::AuditIncidentCause::UntrustedPersistentScript;
                entry.error = None;
            }
            (true, false) => {}
            (true, true) => {
                entry.state = AuditEmergencyScriptQuarantineState::Failed;
                entry.cause = module_audit_log::AuditIncidentCause::ContainmentIncomplete;
                entry.error =
                    Some("startup entry exists at both source and quarantine paths".into());
            }
            (false, false) => {
                entry.state = AuditEmergencyScriptQuarantineState::Failed;
                entry.cause = module_audit_log::AuditIncidentCause::ContainmentIncomplete;
                entry.error = Some("startup entry is missing from both planned paths".into());
            }
        }
        if source_exists && !quarantine_exists && entry.error.is_some() {
            entry.cause = module_audit_log::AuditIncidentCause::PersistentScriptMoveFailed;
        }
        entry.recovery_routes.clear();
    }
}

fn apply_script_quarantine_routes(
    manifests: &mut [AuditEmergencyScriptQuarantineManifest],
    audit_state_verified: bool,
    authorization_configured: bool,
) {
    for entry in manifests
        .iter_mut()
        .flat_map(|manifest| manifest.entries.iter_mut())
    {
        let source_regular_file = std::fs::symlink_metadata(&entry.source_path)
            .is_ok_and(|metadata| metadata.file_type().is_file());
        let quarantine_regular_file = std::fs::symlink_metadata(&entry.quarantine_path)
            .is_ok_and(|metadata| metadata.file_type().is_file());
        entry.recovery_routes = match entry.state {
            AuditEmergencyScriptQuarantineState::Moved => {
                vec![module_audit_assessment::script_delete_route(
                    audit_state_verified,
                    authorization_configured,
                    quarantine_regular_file,
                )]
            }
            AuditEmergencyScriptQuarantineState::Planned
            | AuditEmergencyScriptQuarantineState::Failed
                if source_regular_file && !quarantine_regular_file =>
            {
                vec![module_audit_assessment::script_retry_route(
                    audit_state_verified,
                    authorization_configured,
                    source_regular_file,
                )]
            }
            _ => Vec::new(),
        };
    }
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
    module_audit_transaction::arguments_hash(AuditAction::SecureRemove, &targets)
}

fn secure_remove_targets(module_id: &str) -> Result<Vec<String>> {
    let audit_root = Path::new(defs::MODULE_AUDIT_DIR);
    if let Some(targets) =
        module_audit_transaction::active_targets(audit_root, AuditAction::SecureRemove)?
    {
        ensure!(
            targets == [module_id],
            "requested module does not match the active secure removal operation"
        );
        return Ok(targets);
    }
    let assessed = current_audit_assessment()?;
    ensure!(
        assessed
            .assessment
            .module(module_id)
            .is_some_and(|module| module.disposition.requires_secure_removal()),
        "Module {module_id} does not have an unresolved audit integrity incident"
    );
    Ok(vec![module_id.to_owned()])
}

pub fn secure_remove(module_id: &str, authorization: &str) -> Result<AuditTransactionReceipt> {
    module::validate_module_id(module_id)?;
    ensure!(
        ksucalls::try_check_kernel_safemode()
            .context("query KernelSU safe mode for secure removal")?,
        "Secure module removal requires KernelSU safe mode"
    );
    let targets = secure_remove_targets(module_id)?;
    let arguments_hash =
        module_audit_transaction::arguments_hash(AuditAction::SecureRemove, &targets)?;
    let audit_root = Path::new(defs::MODULE_AUDIT_DIR);
    let mut transaction = AuditTransaction::begin(
        audit_root,
        authorization,
        AuditAction::SecureRemove,
        &arguments_hash,
        &targets,
    )?;
    if transaction.is_committed() {
        return transaction.commit();
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
        transaction.operation_id(),
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
        transaction.operation_id(),
        module_id,
        removed_paths,
    )?;
    transaction.complete_target(module_id)?;
    transaction.commit()
}

pub fn recover_manager_sealed_audit(
    module_id: &str,
    authorization: &str,
) -> Result<(module_audit_log::ModuleAuditStatus, AuditTransactionReceipt)> {
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
                } else if path.file_name().and_then(|name| name.to_str())
                    != Some(SCRIPT_QUARANTINE_MANIFEST_FILE)
                {
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
            audit_state: AuditStateAvailability::Unavailable,
            audit_error: Some("module audit root is missing".into()),
        };

        let error = ensure_activation_outcome_allowed("module.alpha", &outcome).unwrap_err();
        assert!(format!("{error:#}").contains(AUDIT_STATE_UNAVAILABLE_ERROR));
    }

    #[test]
    fn clean_uninitialized_audit_state_still_rejects_module_activation() {
        let outcome = ContainmentOutcome {
            module_ids: Vec::new(),
            audit_state: AuditStateAvailability::CleanUninitialized,
            audit_error: Some("module audit state is not initialized".into()),
        };

        let error = ensure_activation_outcome_allowed("module.alpha", &outcome).unwrap_err();
        assert!(format!("{error:#}").contains(AUDIT_STATE_UNAVAILABLE_ERROR));
    }

    #[test]
    fn verified_containment_rejects_only_affected_module_activation() {
        let outcome = ContainmentOutcome {
            module_ids: vec!["module.alpha".into()],
            audit_state: AuditStateAvailability::Verified,
            audit_error: None,
        };

        let error = ensure_activation_outcome_allowed("module.alpha", &outcome).unwrap_err();
        assert!(format!("{error:#}").contains(AUDIT_MODULE_CONTAINED_ERROR));
        ensure_activation_outcome_allowed("module.beta", &outcome).unwrap();
    }

    #[test]
    fn uninitialized_store_is_clean_only_without_executable_payloads() {
        let temp = tempfile::tempdir().unwrap();
        let audit_root = temp.path().join("audit");
        let modules = temp.path().join("modules");
        let modules_update = temp.path().join("modules_update");
        let service = temp.path().join("service.d");
        let initrc = temp.path().join("initrc.d");
        let metamodule = temp.path().join("metamodule");

        assert!(
            clean_uninitialized_audit_state(
                &audit_root,
                &[&modules, &modules_update],
                &[&service],
                &initrc,
                &metamodule,
            )
            .unwrap()
        );

        std::fs::create_dir_all(&modules).unwrap();
        std::fs::write(modules.join("unexpected"), b"").unwrap();
        assert!(
            !clean_uninitialized_audit_state(
                &audit_root,
                &[&modules, &modules_update],
                &[&service],
                &initrc,
                &metamodule,
            )
            .unwrap()
        );
        std::fs::remove_file(modules.join("unexpected")).unwrap();

        std::fs::create_dir_all(&service).unwrap();
        std::fs::write(service.join("payload.sh"), b"").unwrap();
        assert!(
            !clean_uninitialized_audit_state(
                &audit_root,
                &[&modules, &modules_update],
                &[&service],
                &initrc,
                &metamodule,
            )
            .unwrap()
        );
        std::fs::remove_file(service.join("payload.sh")).unwrap();

        std::fs::create_dir_all(&initrc).unwrap();
        std::fs::write(initrc.join("payload.rc"), b"").unwrap();
        assert!(
            !clean_uninitialized_audit_state(
                &audit_root,
                &[&modules, &modules_update],
                &[&service],
                &initrc,
                &metamodule,
            )
            .unwrap()
        );
        std::fs::remove_file(initrc.join("payload.rc")).unwrap();

        std::fs::write(&metamodule, b"").unwrap();
        assert!(
            !clean_uninitialized_audit_state(
                &audit_root,
                &[&modules, &modules_update],
                &[&service],
                &initrc,
                &metamodule,
            )
            .unwrap()
        );
    }

    #[test]
    fn payload_free_false_positive_emergency_status_is_discarded() {
        let temp = tempfile::tempdir().unwrap();
        let emergency_root = temp.path().join("audit-emergency");
        let status_path = emergency_root.join("status.json");
        persist_active_emergency_status(
            &status_path,
            AuditEmergencyPhase::Contained,
            "audit root is missing",
            Vec::new(),
            &emergency_root,
            Vec::new(),
        )
        .unwrap();

        discard_empty_emergency_status(&status_path, &emergency_root).unwrap();

        assert!(!status_path.exists());
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
        let manifests = read_script_quarantine_manifests(&quarantine)
            .unwrap()
            .manifests;
        assert_eq!(manifests.len(), 1);
        assert_eq!(manifests[0].entries.len(), 2);
        assert!(manifests[0].entries.iter().all(|entry| {
            entry.state == AuditEmergencyScriptQuarantineState::Moved
                && Path::new(&entry.quarantine_path).is_file()
                && !Path::new(&entry.source_path).exists()
        }));
        assert!(regenerated.get());
    }

    #[test]
    fn quarantine_manifest_recovers_move_completed_before_state_commit() {
        let temp = tempfile::tempdir().unwrap();
        let source_dir = temp.path().join("service.d");
        let quarantine_root = temp.path().join("audit-emergency");
        std::fs::create_dir_all(&source_dir).unwrap();
        let source = source_dir.join("payload.sh");
        std::fs::write(&source, b"#!/system/bin/sh\n").unwrap();
        let session = create_emergency_quarantine_session(&quarantine_root).unwrap();
        let destination_dir = session.join("1");
        std::fs::create_dir(&destination_dir).unwrap();
        let destination = destination_dir.join("payload.sh");
        let now = unix_time_seconds();
        let manifest = AuditEmergencyScriptQuarantineManifest {
            schema_version: SCRIPT_QUARANTINE_MANIFEST_SCHEMA_VERSION,
            session_path: session.to_string_lossy().into_owned(),
            entries: vec![AuditEmergencyScriptQuarantineEntry {
                entry_id: script_quarantine_entry_id(&session, &source, &destination),
                cause: module_audit_log::AuditIncidentCause::Unknown,
                source_path: source.to_string_lossy().into_owned(),
                quarantine_path: destination.to_string_lossy().into_owned(),
                state: AuditEmergencyScriptQuarantineState::Planned,
                delete_requested: false,
                error: None,
                recovery_routes: Vec::new(),
            }],
            created_at_unix_seconds: now,
            updated_at_unix_seconds: now,
        };
        write_script_quarantine_manifest(&session, &manifest).unwrap();

        std::fs::rename(&source, &destination).unwrap();

        let manifests = read_script_quarantine_manifests(&quarantine_root)
            .unwrap()
            .manifests;
        assert_eq!(manifests.len(), 1);
        assert_eq!(
            manifests[0].entries[0].state,
            AuditEmergencyScriptQuarantineState::Moved
        );
        assert_eq!(
            manifests[0].entries[0].quarantine_path,
            destination.to_string_lossy()
        );
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
        let manifests = read_script_quarantine_manifests(&quarantine)
            .unwrap()
            .manifests;
        assert_eq!(manifests.len(), 1);
        assert_eq!(manifests[0].entries.len(), 1);
        assert_eq!(
            manifests[0].entries[0].state,
            AuditEmergencyScriptQuarantineState::Moved
        );
        assert!(regenerated.get());
    }
}
