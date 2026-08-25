use anyhow::{Context, Result, bail, ensure};
use ksu_module_audit::AuditReport;
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::module_audit_action::{
    AuditAction, AuditAuthorizationInventory, AuditOperationRecovery,
};

const SCHEMA_VERSION: u32 = 1;
const EVENT_SCHEMA_VERSION: u32 = 2;
const LEGACY_CHECKPOINT_SCHEMA_VERSION: u32 = 6;
const CHECKPOINT_SCHEMA_VERSION: u32 = 7;
const LEGACY_STORE_FORMAT_VERSION: u32 = 1;
const STORE_FORMAT_VERSION: u32 = 2;
const MANAGER_AUTH_SCHEMA_VERSION: u32 = 2;
const KEY_FILE: &str = ".hmac-key";
const MANAGER_AUTH_FILE: &str = "manager-auth.json";
const MANAGER_SEAL_FILE: &str = "manager-seal.json";
const MANAGER_SEAL_SCHEMA_VERSION: u32 = 2;
const NEXT_KEY_FILE: &str = ".hmac-key-next.json";
const OPERATIONS_DIR: &str = "operations";
const CHALLENGES_DIR: &str = "challenges";
const OPERATION_TRASH_DIR: &str = "operation-trash";
const SEALED_RECOVERY_DIR: &str = "sealed-recovery";
const CONTAINMENT_DIR: &str = "containment";
const VERIFIED_SNAPSHOT_ATTEMPTS: usize = 4;
const VERIFIED_SNAPSHOT_RETRY_DELAY: Duration = Duration::from_millis(25);
const AUTH_CHALLENGE_TTL_SECONDS: u64 = 5 * 60;
const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
static ATTEMPT_COUNTER: AtomicU64 = AtomicU64::new(0);

const fn legacy_store_format_version() -> u32 {
    LEGACY_STORE_FORMAT_VERSION
}

#[derive(Debug)]
struct AuditSnapshotChanged;

impl std::fmt::Display for AuditSnapshotChanged {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("audit store changed during verified snapshot")
    }
}

impl std::error::Error for AuditSnapshotChanged {}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallOutcome {
    Installed,
    InstallationFailed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuditEventKind {
    InstallAccepted {
        attempt_id: String,
        report: AuditReport,
    },
    InstallResult {
        attempt_id: String,
        outcome: InstallOutcome,
        error: Option<String>,
    },
    InstalledRescan {
        operation_id: String,
        report: AuditReport,
    },
    InstalledRescanFailed {
        operation_id: String,
        error: String,
    },
    IntegrityIncident {
        corrupted_from_sequence: u64,
        #[serde(default, skip_serializing_if = "AuditIncidentCause::is_unknown")]
        cause: AuditIncidentCause,
        reason: String,
        quarantine: String,
    },
    IncidentClosed {
        incident_id: String,
        operation_id: String,
        resolution: String,
    },
    SecureRemovalCompleted {
        operation_id: String,
        removed_paths: Vec<String>,
    },
    AuditdRestart {
        reason: String,
    },
    ContainmentApplied {
        module_ids: Vec<String>,
    },
    AuditStoreMissing,
    AuditStateUnavailable {
        reason: String,
    },
    AuditVerificationFailed {
        reason: String,
    },
    WatchOverflow,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditEvent {
    pub schema_version: u32,
    pub module_id: String,
    pub sequence: u64,
    pub timestamp_unix_seconds: u64,
    pub previous_hash: String,
    pub kind: AuditEventKind,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct AuthenticatedEvent {
    event: AuditEvent,
    event_hash: String,
    hmac_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(not(any(target_os = "android", test)), allow(dead_code))]
struct PrunedHistoryTombstone {
    schema_version: u32,
    module_id: String,
    cleared_at_unix_seconds: u64,
    previous_event_count: usize,
    previous_head_hash: String,
    previous_event_hashes: Vec<String>,
    had_integrity_incident: bool,
    reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct AuthenticatedRecord<T> {
    record: T,
    hmac_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct PersistentQuarantineRecord {
    schema_version: u32,
    module_id: String,
    uncertain_ownership: bool,
    planned_paths: Vec<String>,
    completed_paths: Vec<String>,
    updated_at_unix_seconds: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
struct PersistentContainmentResultRecord {
    schema_version: u32,
    module_id: String,
    uncertain_ownership: bool,
    quarantined_paths: Vec<String>,
    failures: Vec<String>,
    updated_at_unix_seconds: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainmentState {
    PendingReboot,
    PersistentScriptsIncomplete,
    Contained,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PersistentScriptOwnership {
    Attributed,
    Uncertain,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ModuleContainmentRecord {
    schema_version: u32,
    module_id: String,
    state: ContainmentState,
    updated_at_unix_seconds: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationState {
    Verified,
    Recovered,
    Compromised,
    Empty,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointState {
    NotConfigured,
    Sealed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ModuleAuditStatus {
    pub module_id: String,
    pub verification: VerificationState,
    pub high_risk: bool,
    pub unresolved_risk: bool,
    pub event_count: usize,
    pub head_hash: String,
    pub hmac_verified: bool,
    pub manager_checkpoint: CheckpointState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub containment_state: Option<ContainmentState>,
    pub quarantined_persistent_scripts: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persistent_script_ownership: Option<PersistentScriptOwnership>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub quarantined_persistent_script_paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub persistent_script_failures: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub incidents: Vec<AuditIncidentStatus>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditIncidentCause {
    AuditEventMissing,
    AuditEventInvalid,
    UnexpectedAuditPath,
    IdentityRecordInvalid,
    RiskRecordInvalid,
    HeadRecordInvalid,
    UntrustedPersistentScript,
    PersistentScriptMoveFailed,
    ContainmentIncomplete,
    #[default]
    Unknown,
}

impl AuditIncidentCause {
    pub(crate) fn is_unknown(&self) -> bool {
        *self == Self::Unknown
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditIncidentState {
    Detected,
    Resolved,
    Closed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditRecoveryRequirementState {
    Required,
    Satisfied,
    Unsatisfied,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditRecoveryCondition {
    pub kind: String,
    pub state: AuditRecoveryRequirementState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditRecoveryRoute {
    pub action: String,
    pub available: bool,
    #[serde(default)]
    pub ready: bool,
    pub destructive: bool,
    pub conditions: Vec<AuditRecoveryCondition>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditIncidentStatus {
    pub incident_id: String,
    pub cause: AuditIncidentCause,
    pub state: AuditIncidentState,
    pub detected_at_sequence: u64,
    pub corrupted_from_sequence: u64,
    pub detail: String,
    pub quarantine_path: String,
    pub recovery_routes: Vec<AuditRecoveryRoute>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ModuleAuditHistory {
    pub status: ModuleAuditStatus,
    pub events: Vec<AuditEvent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub integrity_error: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(not(any(target_os = "android", test)), allow(dead_code))]
pub struct StaleAuditHistory {
    pub module_id: String,
    pub event_count: usize,
    pub high_risk: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(not(any(target_os = "android", test)), allow(dead_code))]
pub struct PrunedAuditHistory {
    pub module_id: String,
    pub removed_event_count: usize,
    pub retained_integrity_incident: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CheckpointModuleHead {
    pub module_id: String,
    pub sequence: u64,
    pub head_hash: String,
    pub event_hashes: Vec<String>,
    pub high_risk: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CheckpointTombstone {
    pub module_id: String,
    pub cleared_at_unix_seconds: u64,
    pub previous_event_count: usize,
    pub previous_head_hash: String,
    pub previous_event_hashes: Vec<String>,
    pub had_integrity_incident: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOperationState {
    Applying,
    Applied,
    Interrupted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CheckpointOperation {
    pub operation_id: String,
    pub action: AuditAction,
    pub base_inventory_hash: String,
    pub arguments_hash: String,
    pub authorization_hex: String,
    pub targets: Vec<String>,
    pub completed_targets: Vec<String>,
    pub state: AuditOperationState,
    pub error: Option<String>,
}

/// Canonical payload intended to be signed by the Manager's Android Keystore key.
/// Signature storage and verification deliberately remain a Manager integration concern.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CheckpointPayload {
    pub schema_version: u32,
    #[serde(default = "legacy_store_format_version")]
    pub store_format_version: u32,
    pub created_at_unix_seconds: u64,
    pub hmac_key_id: String,
    pub next_hmac_key_id: String,
    pub inventory_hash: String,
    pub modules: Vec<CheckpointModuleHead>,
    pub tombstones: Vec<CheckpointTombstone>,
    pub operations: Vec<CheckpointOperation>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(not(any(target_os = "android", test)), allow(dead_code))]
pub struct ManagerAuditAuthStatus {
    pub configured: bool,
    pub key_id: Option<String>,
    pub inventory_hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(not(any(target_os = "android", test)), allow(dead_code))]
pub struct ManagerAuditAuthChallenge {
    pub schema_version: u32,
    pub action: AuditAction,
    pub inventory_hash: String,
    pub arguments_hash: String,
    pub key_id: String,
    pub challenge_id: String,
    pub created_at_unix_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ManagerAuditAuthRegistry {
    schema_version: u32,
    public_key_hex: String,
    key_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(not(any(target_os = "android", test)), allow(dead_code))]
struct SignedAuditAuthorization {
    schema_version: u32,
    action: AuditAction,
    inventory_hash: String,
    arguments_hash: String,
    key_id: String,
    challenge_id: String,
    created_at_unix_seconds: u64,
    signature_der_hex: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct AuditAuthorizationChallenge {
    schema_version: u32,
    action: AuditAction,
    inventory_hash: String,
    arguments_hash: String,
    key_id: String,
    challenge_id: String,
    created_at_unix_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct AuditOperationRecord {
    schema_version: u32,
    operation_id: String,
    action: AuditAction,
    base_inventory_hash: String,
    arguments_hash: String,
    authorization_hex: String,
    targets: Vec<String>,
    completed_targets: Vec<String>,
    state: AuditOperationState,
    error: Option<String>,
    started_at_unix_seconds: u64,
    updated_at_unix_seconds: u64,
}

impl AuditOperationRecord {
    fn checkpoint(&self) -> CheckpointOperation {
        CheckpointOperation {
            operation_id: self.operation_id.clone(),
            action: self.action,
            base_inventory_hash: self.base_inventory_hash.clone(),
            arguments_hash: self.arguments_hash.clone(),
            authorization_hex: self.authorization_hex.clone(),
            targets: self.targets.clone(),
            completed_targets: self.completed_targets.clone(),
            state: self.state,
            error: self.error.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AuthorizedAuditOperation {
    pub operation_id: String,
    pub targets: Vec<String>,
    pub completed_targets: Vec<String>,
    pub base_inventory_hash: String,
    pub applied: bool,
    pub replayed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(not(any(target_os = "android", test)), allow(dead_code))]
pub struct ManagerAuditSealStatus {
    pub configured: bool,
    pub generation: Option<u64>,
    pub seal_hash: Option<String>,
    pub inventory_hash: Option<String>,
    pub key_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedIntegrityFailure {
    pub module_id: String,
    pub corrupted_from_sequence: u64,
    pub cause: AuditIncidentCause,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unexpected_paths: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SealedIntegrityStatus {
    pub seal_hash: String,
    pub inventory_hash: String,
    pub failures: Vec<SealedIntegrityFailure>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditInventoryRelation {
    Unsealed,
    SealedCurrent,
    AuthorizedTransition,
    SealedDamage,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerifiedAuditSnapshot {
    pub store_revision: String,
    pub inventory_relation: AuditInventoryRelation,
    pub histories: Vec<ModuleAuditHistory>,
    pub checkpoint: CheckpointPayload,
    pub integrity_failures: Vec<SealedIntegrityFailure>,
    pub seal_status: ManagerAuditSealStatus,
    pub authorization_status: ManagerAuditAuthStatus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerifiedAuditProgress {
    Start {
        total_modules: usize,
    },
    Module {
        module_id: String,
        completed: usize,
        total_modules: usize,
    },
    Checkpoint {
        completed: usize,
        total_modules: usize,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg(test)]
pub struct DashboardCheckpointSnapshot {
    pub checkpoint: CheckpointPayload,
    pub integrity_failures: Vec<SealedIntegrityFailure>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub struct PersistentScriptContainmentPlan {
    pub module_id: String,
    pub paths: Vec<String>,
    pub infer_unattributed: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct PersistentScriptQuarantineOutcome {
    pub completed_paths: Vec<String>,
    pub failures: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct SealedRecoveryRecord {
    schema_version: u32,
    module_id: String,
    operation_id: String,
    seal_hash: String,
    base_inventory_hash: String,
    corrupted_from_sequence: u64,
    #[serde(default, skip_serializing_if = "AuditIncidentCause::is_unknown")]
    cause: AuditIncidentCause,
    reason: String,
    #[serde(default)]
    unexpected_paths: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ManagerCheckpointEnvelope {
    schema_version: u32,
    generation: u64,
    key_backend: String,
    key_protection: String,
    key_id: String,
    payload: String,
    signature: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct StoredManagerSeal {
    envelope_hex: String,
    seal_hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct PendingHmacKey {
    schema_version: u32,
    current_key_id: String,
    next_key_hex: String,
}

impl PendingHmacKey {
    fn next_key(&self) -> Result<[u8; 32]> {
        let bytes = decode_hex(&self.next_key_hex)?;
        bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid pending HMAC key length"))
    }

    fn next_key_id(&self) -> Result<String> {
        Ok(hex(&Sha256::digest(self.next_key()?)))
    }
}

struct VerifiedChain {
    events: Vec<AuthenticatedEvent>,
    state: VerificationState,
}

pub struct AuditReceipt {
    module_id: String,
    attempt_id: String,
}

struct AuditLock {
    #[cfg(unix)]
    file: File,
}

impl AuditLock {
    fn acquire(root: &Path, create_root: bool) -> Result<Self> {
        if create_root {
            ensure_dir(root)?;
        }
        let path = root.join(".lock");
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create(create_root)
            .truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(&path)
            .with_context(|| format!("open module audit lock {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            // SAFETY: flock only observes the valid file descriptor owned by this guard.
            let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
            ensure!(
                result == 0,
                "lock module audit store: {}",
                std::io::Error::last_os_error()
            );
            Ok(Self { file })
        }
        #[cfg(not(unix))]
        {
            let _ = file;
            Ok(Self {})
        }
    }
}

#[cfg(unix)]
impl Drop for AuditLock {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        // SAFETY: the guard still owns a valid descriptor; unlock errors cannot be recovered here.
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

#[cfg_attr(not(any(target_os = "android", test)), allow(dead_code))]
pub fn begin_install(root: &Path, report: AuditReport) -> Result<AuditReceipt> {
    let _lock = AuditLock::acquire(root, true)?;
    let module_id = report
        .module_id
        .clone()
        .context("audited package has no module id")?;
    validate_module_id(&module_id)?;
    let attempt_id = make_attempt_id(&module_id, &report.package_sha256);
    append_event(
        root,
        &module_id,
        AuditEventKind::InstallAccepted {
            attempt_id: attempt_id.clone(),
            report,
        },
    )?;
    Ok(AuditReceipt {
        module_id,
        attempt_id,
    })
}

#[cfg_attr(not(any(target_os = "android", test)), allow(dead_code))]
pub fn finish_install(
    root: &Path,
    receipt: AuditReceipt,
    outcome: InstallOutcome,
    error: Option<String>,
) -> Result<ModuleAuditStatus> {
    let _lock = AuditLock::acquire(root, false)?;
    append_event(
        root,
        &receipt.module_id,
        AuditEventKind::InstallResult {
            attempt_id: receipt.attempt_id,
            outcome,
            error,
        },
    )?;
    verify_module_unlocked(root, &receipt.module_id, true)
}

/// Close install attempts that survived into a new boot without a result.
/// Installer scripts are deliberately never resumed because they are not idempotent.
#[allow(dead_code)]
pub fn recover_interrupted_installs(root: &Path) -> Result<Vec<String>> {
    if !root.join("modules").exists() {
        return Ok(Vec::new());
    }
    let _lock = AuditLock::acquire(root, false)?;
    let key = load_key(root, false)?;
    let mut recovered = Vec::new();
    for module_id in audit_module_ids(&root.join("modules"))? {
        let chain = verify_chain(root, &module_id, &key, true)?;
        let mut pending = Vec::new();
        let mut completed = Vec::new();
        for entry in chain.events {
            match entry.event.kind {
                AuditEventKind::InstallAccepted { attempt_id, .. } => pending.push(attempt_id),
                AuditEventKind::InstallResult { attempt_id, .. } => completed.push(attempt_id),
                _ => {}
            }
        }
        for attempt_id in pending {
            if completed.contains(&attempt_id) {
                continue;
            }
            append_event(
                root,
                &module_id,
                AuditEventKind::InstallResult {
                    attempt_id,
                    outcome: InstallOutcome::InstallationFailed,
                    error: Some(
                        "installation was interrupted before ksud recorded a result".to_owned(),
                    ),
                },
            )?;
            if !recovered.contains(&module_id) {
                recovered.push(module_id.clone());
            }
        }
    }
    Ok(recovered)
}

#[cfg_attr(not(any(target_os = "android", test)), allow(dead_code))]
pub fn record_installed_rescan(
    root: &Path,
    operation_id: &str,
    module_id: &str,
    result: std::result::Result<AuditReport, String>,
) -> Result<ModuleAuditStatus> {
    let _lock = AuditLock::acquire(root, true)?;
    validate_sha256_hex(operation_id, "operation id")?;
    validate_module_id(module_id)?;
    let key = load_key(root, false)?;
    let operation = read_operation(root, operation_id, &key)?
        .context("rescan audit operation is unavailable")?;
    ensure!(
        operation.action == AuditAction::Rescan && operation.state == AuditOperationState::Applying,
        "rescan audit operation is not active"
    );
    ensure!(
        operation.targets.iter().any(|target| target == module_id),
        "module is not part of the authorized rescan"
    );
    if operation
        .completed_targets
        .iter()
        .any(|target| target == module_id)
    {
        return verify_module_unlocked(root, module_id, true);
    }
    let already_recorded = verify_chain(root, module_id, &key, true)?
        .events
        .iter()
        .any(|entry| match &entry.event.kind {
            AuditEventKind::InstalledRescan {
                operation_id: recorded,
                ..
            }
            | AuditEventKind::InstalledRescanFailed {
                operation_id: recorded,
                ..
            } => recorded == operation_id,
            _ => false,
        });
    let kind = match result {
        Ok(report) => {
            ensure!(
                report.module_id.as_deref() == Some(module_id),
                "installed module id does not match module.prop"
            );
            AuditEventKind::InstalledRescan {
                operation_id: operation_id.to_owned(),
                report,
            }
        }
        Err(error) => AuditEventKind::InstalledRescanFailed {
            operation_id: operation_id.to_owned(),
            error,
        },
    };
    if !already_recorded {
        append_event(root, module_id, kind)?;
    }
    verify_module_unlocked(root, module_id, true)
}

#[cfg_attr(not(any(target_os = "android", test)), allow(dead_code))]
pub(crate) fn finish_manager_audit_operation(root: &Path, operation_id: &str) -> Result<()> {
    validate_sha256_hex(operation_id, "operation id")?;
    let _lock = AuditLock::acquire(root, false)?;
    let key = load_key(root, false)?;
    let mut operation =
        read_operation(root, operation_id, &key)?.context("audit operation is unavailable")?;
    if operation.state == AuditOperationState::Applied {
        return Ok(());
    }
    ensure!(
        operation.completed_targets == operation.targets,
        "audit operation still has incomplete targets"
    );
    operation.state = AuditOperationState::Applied;
    operation.updated_at_unix_seconds = now();
    write_record(&operation_path(root, operation_id), operation, &key)
}

pub(crate) fn complete_manager_audit_operation_target(
    root: &Path,
    operation_id: &str,
    expected_action: AuditAction,
    target: &str,
) -> Result<()> {
    validate_sha256_hex(operation_id, "operation id")?;
    let _lock = AuditLock::acquire(root, false)?;
    let key = load_key(root, false)?;
    let mut operation =
        read_operation(root, operation_id, &key)?.context("audit operation is unavailable")?;
    ensure!(
        operation.action == expected_action
            && operation.state == AuditOperationState::Applying
            && operation
                .targets
                .iter()
                .any(|candidate| candidate == target),
        "audit operation target does not match"
    );
    if operation
        .completed_targets
        .iter()
        .any(|completed| completed == target)
    {
        return Ok(());
    }
    operation.completed_targets.push(target.to_owned());
    operation.completed_targets.sort();
    operation.updated_at_unix_seconds = now();
    write_record(&operation_path(root, operation_id), operation, &key)
}

#[cfg(any(not(target_os = "android"), test))]
pub fn verify_module(root: &Path, module_id: &str, repair: bool) -> Result<ModuleAuditStatus> {
    let _lock = AuditLock::acquire(root, false)?;
    verify_module_unlocked(root, module_id, repair)
}

fn incident_cause_from_legacy_reason(reason: &str) -> AuditIncidentCause {
    if reason.contains("identity integrity") {
        AuditIncidentCause::IdentityRecordInvalid
    } else if reason.contains("risk registry integrity") {
        AuditIncidentCause::RiskRecordInvalid
    } else if reason.contains("head integrity") {
        AuditIncidentCause::HeadRecordInvalid
    } else if reason.contains("unexpected entr") {
        AuditIncidentCause::UnexpectedAuditPath
    } else if reason.contains("missing") {
        AuditIncidentCause::AuditEventMissing
    } else if reason.contains("event") || reason.contains("chain") {
        AuditIncidentCause::AuditEventInvalid
    } else {
        AuditIncidentCause::Unknown
    }
}

fn incident_statuses(events: &[AuthenticatedEvent]) -> Vec<AuditIncidentStatus> {
    let last_secure_removal = events
        .iter()
        .filter_map(|entry| match entry.event.kind {
            AuditEventKind::SecureRemovalCompleted { .. } => Some(entry.event.sequence),
            _ => None,
        })
        .max()
        .unwrap_or(0);
    let closed = events
        .iter()
        .filter_map(|entry| match &entry.event.kind {
            AuditEventKind::IncidentClosed { incident_id, .. } => Some(incident_id.clone()),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    events
        .iter()
        .filter_map(|entry| {
            let AuditEventKind::IntegrityIncident {
                corrupted_from_sequence,
                cause,
                reason,
                quarantine,
            } = &entry.event.kind
            else {
                return None;
            };
            let incident_id = entry.event_hash.clone();
            let state = if closed.contains(&incident_id) {
                AuditIncidentState::Closed
            } else if entry.event.sequence < last_secure_removal {
                AuditIncidentState::Resolved
            } else {
                AuditIncidentState::Detected
            };
            Some(AuditIncidentStatus {
                incident_id,
                cause: if cause.is_unknown() {
                    incident_cause_from_legacy_reason(reason)
                } else {
                    *cause
                },
                state,
                detected_at_sequence: entry.event.sequence,
                corrupted_from_sequence: *corrupted_from_sequence,
                detail: reason.clone(),
                quarantine_path: quarantine.clone(),
                recovery_routes: Vec::new(),
            })
        })
        .collect()
}

fn sealed_failure_incident(
    seal_hash: &str,
    failure: &SealedIntegrityFailure,
) -> AuditIncidentStatus {
    let incident_id = hex(&Sha256::digest(
        serde_json::to_vec(&(
            "sealed-integrity",
            seal_hash,
            &failure.module_id,
            failure.corrupted_from_sequence,
            failure.cause,
            &failure.reason,
            &failure.unexpected_paths,
        ))
        .unwrap_or_default(),
    ));
    AuditIncidentStatus {
        incident_id,
        cause: failure.cause,
        state: AuditIncidentState::Detected,
        detected_at_sequence: failure.corrupted_from_sequence,
        corrupted_from_sequence: failure.corrupted_from_sequence,
        detail: failure.reason.clone(),
        quarantine_path: failure.unexpected_paths.join(", "),
        recovery_routes: Vec::new(),
    }
}

fn verify_module_unlocked(root: &Path, module_id: &str, repair: bool) -> Result<ModuleAuditStatus> {
    validate_module_id(module_id)?;
    let key = if repair {
        load_key(root, false)?
    } else {
        read_key(root)?
    };
    Ok(verify_module_with_key_unlocked(root, module_id, repair, &key)?.0)
}

fn verify_module_with_key_unlocked(
    root: &Path,
    module_id: &str,
    repair: bool,
    key: &[u8; 32],
) -> Result<(ModuleAuditStatus, VerifiedChain)> {
    validate_module_id(module_id)?;
    let sealed = verified_sealed_event_hashes(root, module_id, key)?;
    let chain = verify_chain(root, module_id, key, repair)?;
    let high_risk = chain
        .events
        .iter()
        .any(|entry| matches!(entry.event.kind, AuditEventKind::IntegrityIncident { .. }));
    let last_secure_removal = chain
        .events
        .iter()
        .filter_map(|entry| match entry.event.kind {
            AuditEventKind::SecureRemovalCompleted { .. } => Some(entry.event.sequence),
            _ => None,
        })
        .max()
        .unwrap_or(0);
    let unresolved_integrity_risk = chain.events.iter().any(|entry| {
        entry.event.sequence > last_secure_removal
            && matches!(entry.event.kind, AuditEventKind::IntegrityIncident { .. })
    });
    // Static Critical findings are advisory after the user explicitly accepts an install.
    // Only authenticated runtime integrity incidents require containment and secure removal.
    let unresolved_risk = unresolved_integrity_risk;
    let incidents = incident_statuses(&chain.events);
    let head_hash = chain
        .events
        .last()
        .map_or_else(|| GENESIS_HASH.to_owned(), |entry| entry.event_hash.clone());
    let (quarantined_persistent_scripts, persistent_script_ownership) =
        read_persistent_quarantine_summary(root, module_id, key)?;
    let persistent_result = read_persistent_containment_result(root, module_id, key)?;
    let quarantined_persistent_scripts =
        quarantined_persistent_scripts.max(persistent_result.quarantined_paths.len());
    let persistent_script_ownership = if persistent_result.uncertain_ownership {
        Some(PersistentScriptOwnership::Uncertain)
    } else {
        persistent_script_ownership
    };
    let status = ModuleAuditStatus {
        module_id: module_id.to_owned(),
        verification: chain.state,
        high_risk,
        unresolved_risk,
        event_count: chain.events.len(),
        head_hash,
        hmac_verified: true,
        manager_checkpoint: if sealed.is_empty() {
            CheckpointState::NotConfigured
        } else {
            CheckpointState::Sealed
        },
        containment_state: read_containment_state(root, module_id, key)?,
        quarantined_persistent_scripts,
        persistent_script_ownership,
        quarantined_persistent_script_paths: persistent_result.quarantined_paths,
        persistent_script_failures: persistent_result.failures,
        incidents,
    };
    Ok((status, chain))
}

#[cfg(test)]
pub fn module_requires_secure_removal(root: &Path, module_id: &str) -> Result<bool> {
    validate_module_id(module_id)?;
    if !module_path(root, module_id).exists() {
        return Ok(false);
    }
    Ok(verified_audit_snapshot(root)?
        .histories
        .into_iter()
        .find(|history| history.status.module_id == module_id)
        .is_some_and(|history| history.status.unresolved_risk))
}

/// Returns whether a module must be excluded from every execution path.
///
/// Unlike `module_requires_secure_removal`, this remains usable when a Manager-sealed
/// event itself is damaged: the signed seal is then the evidence authorizing a
/// fail-closed containment response.
#[cfg(test)]
pub fn module_requires_containment(root: &Path, module_id: &str) -> Result<bool> {
    validate_module_id(module_id)?;
    let snapshot = verified_audit_snapshot(root)?;
    Ok(snapshot
        .integrity_failures
        .iter()
        .any(|failure| failure.module_id == module_id)
        || snapshot.histories.into_iter().any(|history| {
            history.status.module_id == module_id
                && (history.status.unresolved_risk || history.status.containment_state.is_some())
        }))
}

#[cfg(any(not(target_os = "android"), test))]
pub fn list_modules(root: &Path, repair: bool) -> Result<Vec<ModuleAuditStatus>> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let key = if repair {
        load_key(root, false)?
    } else {
        read_key(root)?
    };
    verify_tombstones(root, &key)?;
    let modules_dir = root.join("modules");
    if !modules_dir.exists() {
        return Ok(Vec::new());
    }
    audit_module_ids(&modules_dir)?
        .iter()
        .map(|module_id| verify_module(root, module_id, repair))
        .collect()
}

fn audit_module_ids(modules_dir: &Path) -> Result<Vec<String>> {
    let mut module_ids = Vec::new();
    for entry in std::fs::read_dir(modules_dir).context("read audit module directory")? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let module_id = entry.file_name().to_string_lossy().into_owned();
        validate_module_id(&module_id)
            .with_context(|| format!("invalid audit module directory {module_id}"))?;
        module_ids.push(module_id);
    }
    module_ids.sort();
    Ok(module_ids)
}

#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub fn dashboard_module_ids(root: &Path) -> Result<Vec<String>> {
    let modules_dir = root.join("modules");
    if !modules_dir.exists() {
        return Ok(Vec::new());
    }
    audit_module_ids(&modules_dir)
}

#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub fn dashboard_store_uninitialized(root: &Path) -> Result<bool> {
    if !root.exists() {
        return Ok(true);
    }
    for entry in std::fs::read_dir(root).context("read module audit root")? {
        if entry?.file_name() != ".lock" {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Content-aware change detector used only to trigger a new full verification.
/// This digest is never accepted as integrity evidence; event HMACs and the
/// Manager seal remain the authority for all dashboard and response decisions.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub fn dashboard_store_revision(root: &Path) -> Result<String> {
    let mut digest = Sha256::new();
    if !root.exists() {
        digest.update(b"missing");
        return Ok(hex(&digest.finalize()));
    }
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let mut entries =
            std::fs::read_dir(&directory)?.collect::<std::result::Result<Vec<_>, _>>()?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let path = entry.path();
            if is_legacy_derived_audit_path(root, &path) {
                continue;
            }
            let metadata = std::fs::symlink_metadata(&path)?;
            digest.update(
                path.strip_prefix(root)
                    .unwrap_or(&path)
                    .as_os_str()
                    .as_encoded_bytes(),
            );
            let file_type = metadata.file_type();
            digest.update([
                u8::from(file_type.is_dir()),
                u8::from(file_type.is_symlink()),
            ]);
            if file_type.is_dir() {
                pending.push(path);
            } else if file_type.is_file() {
                digest.update(metadata.len().to_le_bytes());
                let mut file = File::open(&path)
                    .with_context(|| format!("open audit dashboard input {}", path.display()))?;
                let mut buffer = [0_u8; 8192];
                loop {
                    let read = file.read(&mut buffer)?;
                    if read == 0 {
                        break;
                    }
                    digest.update(&buffer[..read]);
                }
            } else if file_type.is_symlink() {
                digest.update(std::fs::read_link(&path)?.as_os_str().as_encoded_bytes());
            }
        }
    }
    Ok(hex(&digest.finalize()))
}

fn is_legacy_derived_audit_path(root: &Path, path: &Path) -> bool {
    let Ok(relative) = path.strip_prefix(root) else {
        return false;
    };
    if relative.starts_with("risk") {
        return true;
    }
    relative.starts_with("modules")
        && relative.components().count() == 3
        && matches!(
            relative.file_name().and_then(std::ffi::OsStr::to_str),
            Some("identity.json" | "head.json")
        )
}

pub fn read_module_history(
    root: &Path,
    module_id: &str,
    repair: bool,
) -> Result<ModuleAuditHistory> {
    let _lock = AuditLock::acquire(root, false)?;
    let key = if repair {
        load_key(root, false)?
    } else {
        read_key(root)?
    };
    verify_tombstones(root, &key)?;
    read_module_history_unlocked(root, module_id, repair, &key)
}

fn read_module_history_unlocked(
    root: &Path,
    module_id: &str,
    repair: bool,
    key: &[u8; 32],
) -> Result<ModuleAuditHistory> {
    let (status, chain) = verify_module_with_key_unlocked(root, module_id, repair, key)?;
    let events = chain
        .events
        .into_iter()
        .map(|entry| entry.event)
        .collect::<Vec<_>>();
    Ok(ModuleAuditHistory {
        status,
        events,
        integrity_error: None,
    })
}

#[cfg(any(not(target_os = "android"), test))]
pub fn list_histories(root: &Path, repair: bool) -> Result<Vec<ModuleAuditHistory>> {
    list_modules(root, repair)?
        .into_iter()
        .map(|status| read_module_history(root, &status.module_id, false))
        .collect()
}

#[cfg_attr(not(any(target_os = "android", test)), allow(dead_code))]
pub fn read_module_history_resilient(
    root: &Path,
    module_id: &str,
    repair: bool,
) -> Result<ModuleAuditHistory> {
    match read_module_history(root, module_id, repair) {
        Ok(history) => Ok(history),
        Err(error) => compromised_sealed_history(root, module_id, &error),
    }
}

fn read_module_history_resilient_unlocked(
    root: &Path,
    module_id: &str,
    key: &[u8; 32],
) -> Result<ModuleAuditHistory> {
    match read_module_history_unlocked(root, module_id, false, key) {
        Ok(history) => Ok(history),
        Err(error) => compromised_sealed_history_unlocked(root, module_id, &error, key),
    }
}

#[cfg_attr(not(any(target_os = "android", test)), allow(dead_code))]
pub fn list_histories_resilient(root: &Path, repair: bool) -> Result<Vec<ModuleAuditHistory>> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let key = if repair {
        load_key(root, false)?
    } else {
        read_key(root)?
    };
    verify_tombstones(root, &key)?;
    let modules_dir = root.join("modules");
    if !modules_dir.exists() {
        return Ok(Vec::new());
    }
    audit_module_ids(&modules_dir)?
        .into_iter()
        .map(|module_id| read_module_history_resilient(root, &module_id, repair))
        .collect()
}

#[cfg_attr(not(any(target_os = "android", test)), allow(dead_code))]
pub fn list_modules_resilient(root: &Path, repair: bool) -> Result<Vec<ModuleAuditStatus>> {
    Ok(list_histories_resilient(root, repair)?
        .into_iter()
        .map(|history| history.status)
        .collect())
}

fn compromised_sealed_history(
    root: &Path,
    module_id: &str,
    source: &anyhow::Error,
) -> Result<ModuleAuditHistory> {
    let _lock = AuditLock::acquire(root, false)?;
    let key = read_key(root)?;
    compromised_sealed_history_unlocked(root, module_id, source, &key)
}

fn compromised_sealed_history_unlocked(
    root: &Path,
    module_id: &str,
    source: &anyhow::Error,
    key: &[u8; 32],
) -> Result<ModuleAuditHistory> {
    let registry = read_manager_auth_registry(root, &key)?
        .context("Manager audit authorization key is not configured")?;
    let seal = load_verified_manager_seal(root, &registry)?
        .context("Manager audit seal is not configured")?;
    let module = seal
        .payload
        .modules
        .iter()
        .find(|module| module.module_id == module_id)
        .context("failed audit module is not present in the Manager seal")?;
    let failure = diagnose_sealed_module(root, module)?
        .with_context(|| format!("audit history failed without sealed damage: {source:#}"))?;
    let (quarantined_persistent_scripts, persistent_script_ownership) =
        read_persistent_quarantine_summary(root, module_id, &key)?;
    let persistent_result = read_persistent_containment_result(root, module_id, &key)?;
    let quarantined_persistent_scripts =
        quarantined_persistent_scripts.max(persistent_result.quarantined_paths.len());
    let persistent_script_ownership = if persistent_result.uncertain_ownership {
        Some(PersistentScriptOwnership::Uncertain)
    } else {
        persistent_script_ownership
    };
    Ok(ModuleAuditHistory {
        status: ModuleAuditStatus {
            module_id: module_id.to_owned(),
            verification: VerificationState::Compromised,
            high_risk: true,
            unresolved_risk: true,
            event_count: module.event_hashes.len(),
            head_hash: module.head_hash.clone(),
            hmac_verified: false,
            manager_checkpoint: CheckpointState::Sealed,
            containment_state: read_containment_state(root, module_id, &key)?,
            quarantined_persistent_scripts,
            persistent_script_ownership,
            quarantined_persistent_script_paths: persistent_result.quarantined_paths,
            persistent_script_failures: persistent_result.failures,
            incidents: vec![sealed_failure_incident(&seal.seal_hash, &failure)],
        },
        events: Vec::new(),
        integrity_error: Some(format!(
            "Manager-sealed event {} failed verification: {}",
            failure.corrupted_from_sequence, failure.reason
        )),
    })
}

#[cfg_attr(not(any(target_os = "android", test)), allow(dead_code))]
pub fn list_stale_histories(
    root: &Path,
    installed_modules_root: &Path,
    pending_modules_root: &Path,
) -> Result<Vec<StaleAuditHistory>> {
    if !root.exists() || !root.join("modules").exists() {
        return Ok(Vec::new());
    }
    Ok(stale_histories_from_verified(
        &verified_audit_snapshot(root)?.histories,
        installed_modules_root,
        pending_modules_root,
    ))
}

#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub fn stale_histories_from_verified(
    histories: &[ModuleAuditHistory],
    installed_modules_root: &Path,
    pending_modules_root: &Path,
) -> Vec<StaleAuditHistory> {
    histories
        .iter()
        .filter(|history| {
            !installed_module_exists(
                installed_modules_root,
                pending_modules_root,
                &history.status.module_id,
            )
        })
        .map(|history| StaleAuditHistory {
            module_id: history.status.module_id.clone(),
            event_count: history.status.event_count,
            high_risk: history.status.high_risk,
        })
        .collect()
}

#[cfg_attr(not(any(target_os = "android", test)), allow(dead_code))]
pub fn prune_stale_histories(
    root: &Path,
    installed_modules_root: &Path,
    pending_modules_root: &Path,
    operation_id: &str,
) -> Result<Vec<PrunedAuditHistory>> {
    validate_sha256_hex(operation_id, "operation id")?;
    let _lock = AuditLock::acquire(root, false)?;
    let key = load_key(root, false)?;
    verify_tombstones(root, &key)?;
    let mut operation = read_operation(root, operation_id, &key)?
        .context("cleanup audit operation is unavailable")?;
    ensure!(
        operation.action == AuditAction::Prune && operation.state == AuditOperationState::Applying,
        "cleanup audit operation is not active"
    );

    let mut pruned = Vec::new();
    for module_id in operation.targets.clone() {
        if operation.completed_targets.contains(&module_id) {
            continue;
        }
        validate_module_id(&module_id)?;
        if installed_module_exists(installed_modules_root, pending_modules_root, &module_id) {
            let error = "module was installed while its audit history was being cleared";
            operation.state = AuditOperationState::Interrupted;
            operation.error = Some(error.to_owned());
            operation.updated_at_unix_seconds = now();
            write_record(&operation_path(root, operation_id), operation, &key)?;
            bail!(error);
        }
        let live = module_path(root, &module_id);
        let trash = operation_trash_path(root, operation_id, &module_id);
        let tombstone_path = operation_tombstone_path(root, &module_id, operation_id);
        let tombstone = if tombstone_path.exists() {
            let authenticated: AuthenticatedRecord<PrunedHistoryTombstone> =
                read_json(&tombstone_path)?;
            verify_record(&authenticated.record, &authenticated.hmac_sha256, &key)?;
            ensure!(
                authenticated.record.module_id == module_id
                    && authenticated.record.reason == format!("user_cleanup:{operation_id}"),
                "cleanup tombstone does not match its operation"
            );
            authenticated.record
        } else {
            ensure!(
                live.exists(),
                "module audit history is unavailable for cleanup"
            );
            let status = verify_module_unlocked(root, &module_id, true)?;
            let event_hashes = verify_chain(root, &module_id, &key, false)?
                .events
                .into_iter()
                .map(|event| event.event_hash)
                .collect();
            let tombstone = PrunedHistoryTombstone {
                schema_version: SCHEMA_VERSION,
                module_id: module_id.clone(),
                cleared_at_unix_seconds: now(),
                previous_event_count: status.event_count,
                previous_head_hash: status.head_hash,
                previous_event_hashes: event_hashes,
                had_integrity_incident: status.high_risk,
                reason: format!("user_cleanup:{operation_id}"),
            };
            write_record(&tombstone_path, tombstone.clone(), &key)?;
            tombstone
        };

        if installed_module_exists(installed_modules_root, pending_modules_root, &module_id) {
            let error = "module was reinstalled while its audit history was being cleared";
            operation.state = AuditOperationState::Interrupted;
            operation.error = Some(error.to_owned());
            operation.updated_at_unix_seconds = now();
            write_record(&operation_path(root, operation_id), operation, &key)?;
            bail!(error);
        }
        if live.exists() {
            ensure!(!trash.exists(), "cleanup trash destination already exists");
            ensure_dir(trash.parent().context("cleanup trash has no parent")?)?;
            std::fs::rename(&live, &trash)
                .with_context(|| format!("quarantine audit history for {module_id}"))?;
            sync_dir(live.parent().context("audit history has no parent")?)?;
            sync_dir(trash.parent().context("cleanup trash has no parent")?)?;
        } else {
            ensure!(
                trash.exists(),
                "cleaned audit history and its quarantine are missing"
            );
        }
        pruned.push(PrunedAuditHistory {
            module_id,
            removed_event_count: tombstone.previous_event_count,
            retained_integrity_incident: tombstone.had_integrity_incident,
        });
    }
    Ok(pruned)
}

#[cfg_attr(not(any(target_os = "android", test)), allow(dead_code))]
pub fn quarantine_module_for_secure_removal(
    root: &Path,
    installed_modules_root: &Path,
    pending_modules_root: &Path,
    operation_id: &str,
    module_id: &str,
) -> Result<Vec<String>> {
    validate_sha256_hex(operation_id, "operation id")?;
    validate_module_id(module_id)?;
    let _lock = AuditLock::acquire(root, false)?;
    let key = load_key(root, false)?;
    let operation = read_operation(root, operation_id, &key)?
        .context("secure removal audit operation is unavailable")?;
    ensure!(
        operation.action == AuditAction::SecureRemove
            && operation.state == AuditOperationState::Applying
            && operation.targets == [module_id],
        "secure removal audit operation is not active"
    );
    ensure!(
        verify_module_unlocked(root, module_id, true)?.unresolved_risk,
        "module does not have an unresolved audit integrity incident"
    );

    let trash_root = root
        .join(OPERATION_TRASH_DIR)
        .join(operation_id)
        .join("module-content");
    let candidates = [
        (installed_modules_root.join(module_id), "installed"),
        (pending_modules_root.join(module_id), "pending"),
    ];
    let mut removed_paths = Vec::new();
    for (source, label) in candidates {
        let destination = trash_root.join(label);
        if source.exists() {
            ensure!(
                !destination.exists(),
                "secure removal quarantine destination already exists"
            );
            ensure_dir(
                destination
                    .parent()
                    .context("removal trash has no parent")?,
            )?;
            std::fs::rename(&source, &destination)
                .with_context(|| format!("quarantine untrusted module {module_id}"))?;
            sync_dir(source.parent().context("module path has no parent")?)?;
            sync_dir(
                destination
                    .parent()
                    .context("removal trash has no parent")?,
            )?;
        }
        if destination.exists() {
            removed_paths.push(source.to_string_lossy().into_owned());
        }
    }
    ensure!(
        !removed_paths.is_empty(),
        "module content and secure removal quarantine are both missing"
    );
    Ok(removed_paths)
}

#[cfg_attr(not(any(target_os = "android", test)), allow(dead_code))]
pub fn complete_secure_module_removal(
    root: &Path,
    operation_id: &str,
    module_id: &str,
    mut removed_paths: Vec<String>,
) -> Result<ModuleAuditStatus> {
    validate_sha256_hex(operation_id, "operation id")?;
    validate_module_id(module_id)?;
    removed_paths.sort();
    removed_paths.dedup();
    ensure!(
        !removed_paths.is_empty(),
        "secure removal removed no module paths"
    );
    let _lock = AuditLock::acquire(root, false)?;
    let key = load_key(root, false)?;
    let operation = read_operation(root, operation_id, &key)?
        .context("secure removal audit operation is unavailable")?;
    ensure!(
        operation.action == AuditAction::SecureRemove
            && operation.state == AuditOperationState::Applying
            && operation.targets == [module_id],
        "secure removal audit operation is not active"
    );
    let already_recorded = verify_chain(root, module_id, &key, true)?
        .events
        .iter()
        .any(|entry| {
            matches!(
                &entry.event.kind,
                AuditEventKind::SecureRemovalCompleted { operation_id: recorded, .. }
                    if recorded == operation_id
            )
        });
    if !already_recorded {
        append_event(
            root,
            module_id,
            AuditEventKind::SecureRemovalCompleted {
                operation_id: operation_id.to_owned(),
                removed_paths,
            },
        )?;
    }
    clear_completed_containment_state(root, module_id, &key)?;
    verify_module_unlocked(root, module_id, true)
}

#[cfg_attr(not(any(target_os = "android", test)), allow(dead_code))]
fn installed_module_exists(
    installed_modules_root: &Path,
    pending_modules_root: &Path,
    module_id: &str,
) -> bool {
    [installed_modules_root, pending_modules_root]
        .iter()
        .any(|root| root.join(module_id).join("module.prop").is_file())
}

fn verify_tombstones(root: &Path, key: &[u8; 32]) -> Result<()> {
    verified_tombstones(root, key).map(|_| ())
}

fn verified_operations(root: &Path, key: &[u8; 32]) -> Result<Vec<CheckpointOperation>> {
    let mut operations = read_operation_records(root, key)?
        .into_iter()
        .map(|operation| operation.checkpoint())
        .collect::<Vec<_>>();
    operations.sort_by(|left, right| left.operation_id.cmp(&right.operation_id));
    Ok(operations)
}

fn read_operation_records(root: &Path, key: &[u8; 32]) -> Result<Vec<AuditOperationRecord>> {
    let directory = root.join(OPERATIONS_DIR);
    if !directory.exists() {
        return Ok(Vec::new());
    }
    let mut operations = Vec::new();
    for entry in std::fs::read_dir(&directory).context("read audit operation directory")? {
        let entry = entry?;
        if !entry.file_type()?.is_file()
            || entry.path().extension().is_none()
            || entry
                .path()
                .extension()
                .is_some_and(|extension| extension != "json")
        {
            continue;
        }
        let authenticated: AuthenticatedRecord<AuditOperationRecord> = read_json(&entry.path())?;
        verify_record(&authenticated.record, &authenticated.hmac_sha256, key)?;
        validate_operation_record(&authenticated.record)?;
        operations.push(authenticated.record);
    }
    operations.sort_by(|left, right| left.operation_id.cmp(&right.operation_id));
    Ok(operations)
}

fn validate_operation_record(operation: &AuditOperationRecord) -> Result<()> {
    ensure!(
        operation.schema_version == SCHEMA_VERSION,
        "unsupported audit operation schema"
    );
    validate_sha256_hex(&operation.operation_id, "operation id")?;
    validate_sha256_hex(&operation.base_inventory_hash, "base inventory hash")?;
    validate_sha256_hex(&operation.arguments_hash, "operation arguments hash")?;
    ensure!(
        !operation.authorization_hex.is_empty()
            && operation.authorization_hex.len() <= 64 * 1024
            && operation
                .authorization_hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit()),
        "invalid audit operation authorization"
    );
    ensure!(
        operation
            .completed_targets
            .iter()
            .all(|target| operation.targets.contains(target)),
        "audit operation completed an unknown target"
    );
    ensure!(
        operation
            .completed_targets
            .windows(2)
            .all(|pair| pair[0] < pair[1]),
        "audit operation completed targets are not canonical"
    );
    ensure!(
        operation.targets.windows(2).all(|pair| pair[0] < pair[1]),
        "audit operation targets are not canonical"
    );
    if operation.state == AuditOperationState::Applied {
        ensure!(
            operation.completed_targets == operation.targets,
            "applied audit operation is incomplete"
        );
    }
    ensure!(
        (operation.state == AuditOperationState::Interrupted) == operation.error.is_some(),
        "audit operation interruption state is inconsistent"
    );
    ensure!(
        operation
            .error
            .as_ref()
            .is_none_or(|error| !error.is_empty() && error.len() <= 4096),
        "invalid audit operation error"
    );
    Ok(())
}

fn verified_tombstones(root: &Path, key: &[u8; 32]) -> Result<Vec<PrunedHistoryTombstone>> {
    let tombstones_root = root.join("tombstones");
    if !tombstones_root.exists() {
        return Ok(Vec::new());
    }
    let mut tombstones = Vec::new();
    for module_entry in
        std::fs::read_dir(&tombstones_root).context("read audit tombstone directory")?
    {
        let module_entry = module_entry?;
        ensure!(
            module_entry.file_type()?.is_dir(),
            "unexpected file in audit tombstone directory"
        );
        let module_id = module_entry.file_name().to_string_lossy().into_owned();
        validate_module_id(&module_id)?;
        for entry in std::fs::read_dir(module_entry.path()).context("read module tombstones")? {
            let entry = entry?;
            ensure!(entry.file_type()?.is_file(), "unexpected tombstone entry");
            let tombstone: AuthenticatedRecord<PrunedHistoryTombstone> = read_json(&entry.path())?;
            verify_record(&tombstone.record, &tombstone.hmac_sha256, key)?;
            ensure!(
                tombstone.record.schema_version == SCHEMA_VERSION,
                "unsupported audit tombstone schema"
            );
            ensure!(
                tombstone.record.module_id == module_id,
                "audit tombstone module id mismatch"
            );
            ensure!(
                tombstone.record.previous_event_hashes.len()
                    == tombstone.record.previous_event_count,
                "audit tombstone event hash count mismatch"
            );
            ensure!(
                tombstone.record.previous_event_hashes.last()
                    == Some(&tombstone.record.previous_head_hash),
                "audit tombstone head hash mismatch"
            );
            tombstones.push(tombstone.record);
        }
    }
    tombstones.sort_by(|left, right| {
        left.module_id
            .cmp(&right.module_id)
            .then_with(|| {
                left.cleared_at_unix_seconds
                    .cmp(&right.cleared_at_unix_seconds)
            })
            .then_with(|| left.previous_head_hash.cmp(&right.previous_head_hash))
    });
    Ok(tombstones)
}

pub fn checkpoint_payload(root: &Path) -> Result<CheckpointPayload> {
    Ok(verified_audit_snapshot(root)?.checkpoint)
}

/// Create the authentication material for a genuinely empty audit store.
///
/// This is used only while the Manager holds an audit installation session so
/// it can seal an empty baseline before the first module installation creates
/// an operation record.  Never initialize over pre-existing store content:
/// doing so would let a newly-installed Manager bless unauthenticated history.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub fn initialize_empty_store(root: &Path) -> Result<()> {
    let _lock = AuditLock::acquire(root, true)?;
    ensure!(
        dashboard_store_uninitialized(root)?,
        "refusing to initialize a non-empty module audit store"
    );
    load_key(root, true)?;
    Ok(())
}

/// Resume crash-safe store maintenance from an explicit mutation boundary.
/// Verification and policy callers must use `verified_audit_snapshot` instead.
pub fn repair_audit_store(root: &Path) -> Result<()> {
    if dashboard_store_uninitialized(root)? {
        return Ok(());
    }
    let _lock = AuditLock::acquire(root, false)?;
    let key = load_key(root, false)?;
    remove_legacy_derived_state_unlocked(root)?;
    recover_operation_progress(root, &key)?;
    let registry = read_manager_auth_registry(root, &key)?;
    if let Some(seal) = match &registry {
        Some(registry) => load_verified_manager_seal(root, registry)?,
        None => None,
    } {
        finalize_sealed_recovery_records(root, &seal.payload)?;
        finalize_sealed_operation_trash(root, &seal.payload)?;
    }
    Ok(())
}

/// Remove v1 metadata that duplicated authenticated event-chain state.
///
/// v2 readers never consult these paths, so every individual removal is an
/// idempotent cleanup rather than a trust transition.  A crash can leave only
/// ignored v1 files behind; the next maintenance pass safely resumes removal.
pub fn migrate_audit_store_v2(root: &Path) -> Result<()> {
    if dashboard_store_uninitialized(root)? {
        return Ok(());
    }
    let _lock = AuditLock::acquire(root, false)?;
    read_key(root)?;
    remove_legacy_derived_state_unlocked(root)
}

fn remove_legacy_derived_state_unlocked(root: &Path) -> Result<()> {
    remove_legacy_path(&root.join("risk"))?;
    let modules = root.join("modules");
    if modules.exists() {
        for module_id in audit_module_ids(&modules)? {
            let module = module_path(root, &module_id);
            remove_legacy_path(&module.join("identity.json"))?;
            remove_legacy_path(&module.join("head.json"))?;
        }
    }
    Ok(())
}

fn remove_legacy_path(path: &Path) -> Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect legacy audit path {}", path.display()));
        }
    };
    if metadata.file_type().is_dir() {
        std::fs::remove_dir_all(path)
            .with_context(|| format!("remove legacy audit directory {}", path.display()))?;
    } else {
        std::fs::remove_file(path)
            .with_context(|| format!("remove legacy audit file {}", path.display()))?;
    }
    sync_dir(path.parent().context("legacy audit path has no parent")?)
}

fn checkpoint_payload_unlocked(root: &Path) -> Result<CheckpointPayload> {
    let key = read_key(root)?;
    checkpoint_payload_readonly_unlocked(root, &key)
}

fn checkpoint_payload_readonly_unlocked(root: &Path, key: &[u8; 32]) -> Result<CheckpointPayload> {
    let tombstones = verified_tombstones(root, key)?
        .into_iter()
        .map(|tombstone| CheckpointTombstone {
            module_id: tombstone.module_id,
            cleared_at_unix_seconds: tombstone.cleared_at_unix_seconds,
            previous_event_count: tombstone.previous_event_count,
            previous_head_hash: tombstone.previous_head_hash,
            previous_event_hashes: tombstone.previous_event_hashes,
            had_integrity_incident: tombstone.had_integrity_incident,
        })
        .collect::<Vec<CheckpointTombstone>>();
    let modules_dir = root.join("modules");
    let modules = if modules_dir.exists() {
        audit_module_ids(&modules_dir)?
            .into_iter()
            .map(|module_id| verify_module_unlocked(root, &module_id, false))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .map(|status| {
                let event_hashes = verify_chain(root, &status.module_id, key, false)?
                    .events
                    .into_iter()
                    .map(|event| event.event_hash)
                    .collect();
                Ok(CheckpointModuleHead {
                    module_id: status.module_id,
                    sequence: u64::try_from(status.event_count).unwrap_or(u64::MAX),
                    head_hash: status.head_hash,
                    event_hashes,
                    high_risk: status.high_risk,
                })
            })
            .collect::<Result<Vec<_>>>()?
    } else {
        Vec::new()
    };
    let operations = verified_operations(root, key)?;
    let hmac_key_id = hex(&Sha256::digest(key));
    let next_hmac_key_id =
        next_hmac_key_id_for_checkpoint(root, key, &modules, &tombstones, &operations)?;
    let inventory_hash = checkpoint_inventory_hash(
        CHECKPOINT_SCHEMA_VERSION,
        STORE_FORMAT_VERSION,
        &hmac_key_id,
        &next_hmac_key_id,
        &modules,
        &tombstones,
        &operations,
    )?;
    Ok(CheckpointPayload {
        schema_version: CHECKPOINT_SCHEMA_VERSION,
        store_format_version: STORE_FORMAT_VERSION,
        created_at_unix_seconds: now(),
        hmac_key_id,
        next_hmac_key_id,
        inventory_hash,
        modules,
        tombstones,
        operations,
    })
}

fn recover_operation_progress(root: &Path, key: &[u8; 32]) -> Result<()> {
    let directory = root.join(OPERATIONS_DIR);
    if !directory.exists() {
        return Ok(());
    }
    for entry in std::fs::read_dir(&directory).context("recover audit operations")? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let authenticated: AuthenticatedRecord<AuditOperationRecord> = read_json(&entry.path())?;
        verify_record(&authenticated.record, &authenticated.hmac_sha256, key)?;
        let mut operation = authenticated.record;
        validate_operation_record(&operation)?;
        if operation.state != AuditOperationState::Applying {
            continue;
        }
        let mut changed = false;
        for target in &operation.targets {
            if operation.completed_targets.contains(target) {
                continue;
            }
            let completed = match operation.action.descriptor().recovery {
                AuditOperationRecovery::RescanEvent => {
                    operation_rescan_event_exists(root, target, &operation.operation_id, key)?
                }
                AuditOperationRecovery::PruneArtifacts => {
                    recover_prune_completion(root, target, &operation.operation_id)?
                }
                AuditOperationRecovery::SecureRemovalEvent => {
                    recover_secure_removal_completion(root, target, &operation.operation_id, key)?
                }
                AuditOperationRecovery::SealedRecoveryRecord => {
                    operation_sealed_recovery_exists(root, target, &operation.operation_id, key)?
                }
                AuditOperationRecovery::IncidentCloseEvent => {
                    operation_incident_close_exists(root, target, &operation.operation_id, key)?
                }
                AuditOperationRecovery::QuarantinedScriptState => {
                    crate::module_response::quarantined_script_action_completed(
                        target,
                        operation.action,
                    )?
                }
            };
            if completed {
                operation.completed_targets.push(target.clone());
                changed = true;
            }
        }
        operation.completed_targets.sort();
        if operation.completed_targets == operation.targets {
            operation.state = AuditOperationState::Applied;
            changed = true;
        }
        if changed {
            operation.updated_at_unix_seconds = now();
            write_record(&entry.path(), operation, key)?;
        }
    }
    Ok(())
}

fn recover_prune_completion(root: &Path, module_id: &str, operation_id: &str) -> Result<bool> {
    let live = module_path(root, module_id);
    let trash = operation_trash_path(root, operation_id, module_id);
    let tombstone = operation_tombstone_path(root, module_id, operation_id);
    if !trash.exists() || !tombstone.exists() {
        return Ok(false);
    }
    ensure!(
        !live.exists(),
        "cleanup recovery found both live and quarantined audit histories"
    );
    Ok(true)
}

fn operation_rescan_event_exists(
    root: &Path,
    module_id: &str,
    operation_id: &str,
    key: &[u8; 32],
) -> Result<bool> {
    if !module_path(root, module_id).exists() {
        return Ok(false);
    }
    Ok(verify_chain(root, module_id, key, true)?
        .events
        .iter()
        .any(|entry| match &entry.event.kind {
            AuditEventKind::InstalledRescan {
                operation_id: recorded,
                ..
            }
            | AuditEventKind::InstalledRescanFailed {
                operation_id: recorded,
                ..
            } => recorded == operation_id,
            _ => false,
        }))
}

fn operation_secure_removal_event_exists(
    root: &Path,
    module_id: &str,
    operation_id: &str,
    key: &[u8; 32],
) -> Result<bool> {
    if !module_path(root, module_id).exists() {
        return Ok(false);
    }
    Ok(verify_chain(root, module_id, key, true)?
        .events
        .iter()
        .any(|entry| {
            matches!(
                &entry.event.kind,
                AuditEventKind::SecureRemovalCompleted { operation_id: recorded, .. }
                    if recorded == operation_id
            )
        }))
}

fn recover_secure_removal_completion(
    root: &Path,
    module_id: &str,
    operation_id: &str,
    key: &[u8; 32],
) -> Result<bool> {
    let completed = operation_secure_removal_event_exists(root, module_id, operation_id, key)?;
    if completed {
        clear_completed_containment_state(root, module_id, key)?;
    }
    Ok(completed)
}

fn operation_sealed_recovery_exists(
    root: &Path,
    module_id: &str,
    operation_id: &str,
    key: &[u8; 32],
) -> Result<bool> {
    let Some(recovery) = read_sealed_recovery(root, module_id, key)? else {
        return Ok(false);
    };
    if recovery.operation_id != operation_id {
        return Ok(false);
    }
    Ok(verify_chain(root, module_id, key, true)?
        .events
        .last()
        .is_some_and(|entry| {
            entry.event.sequence == recovery.corrupted_from_sequence
                && matches!(entry.event.kind, AuditEventKind::IntegrityIncident { .. })
        }))
}

fn operation_incident_close_exists(
    root: &Path,
    module_id: &str,
    operation_id: &str,
    key: &[u8; 32],
) -> Result<bool> {
    if !module_path(root, module_id).exists() {
        return Ok(false);
    }
    Ok(verify_chain(root, module_id, key, true)?
        .events
        .iter()
        .any(|entry| {
            matches!(
                &entry.event.kind,
                AuditEventKind::IncidentClosed { operation_id: recorded, .. }
                    if recorded == operation_id
            )
        }))
}

#[allow(dead_code)]
pub(crate) fn active_manager_audit_operation_targets(
    root: &Path,
    action: AuditAction,
) -> Result<Option<Vec<String>>> {
    let _lock = AuditLock::acquire(root, false)?;
    let key = load_key(root, false)?;
    let active = read_operation_records(root, &key)?
        .into_iter()
        .filter(|operation| {
            operation.state == AuditOperationState::Applying && operation.action == action
        })
        .collect::<Vec<_>>();
    ensure!(
        active.len() <= 1,
        "multiple active audit operations require recovery"
    );
    Ok(active.into_iter().next().map(|operation| operation.targets))
}

fn next_hmac_key_id_for_checkpoint(
    root: &Path,
    key: &[u8; 32],
    modules: &[CheckpointModuleHead],
    tombstones: &[CheckpointTombstone],
    operations: &[CheckpointOperation],
) -> Result<String> {
    let current_key_id = hmac_key_id(key);
    let registry = read_manager_auth_registry(root, key)?;
    let seal = match registry {
        Some(registry) => load_verified_manager_seal(root, &registry)?,
        None => None,
    };
    let has_unsealed_state = seal.map_or(
        !modules.is_empty() || !tombstones.is_empty() || !operations.is_empty(),
        |seal| {
            seal.payload.modules != modules
                || seal.payload.tombstones != tombstones
                || seal.payload.operations != operations
        },
    );
    if has_unsealed_state {
        let pending_path = root.join(NEXT_KEY_FILE);
        if pending_path.exists() {
            pending_hmac_key(root, key, false)?.next_key_id()
        } else {
            Ok(current_key_id)
        }
    } else {
        Ok(current_key_id)
    }
}

fn checkpoint_inventory_hash(
    schema_version: u32,
    store_format_version: u32,
    hmac_key_id: &str,
    next_hmac_key_id: &str,
    modules: &[CheckpointModuleHead],
    tombstones: &[CheckpointTombstone],
    operations: &[CheckpointOperation],
) -> Result<String> {
    #[derive(Serialize)]
    struct LegacyInventory<'a> {
        schema_version: u32,
        hmac_key_id: &'a str,
        next_hmac_key_id: &'a str,
        modules: &'a [CheckpointModuleHead],
        tombstones: &'a [CheckpointTombstone],
        operations: &'a [CheckpointOperation],
    }

    #[derive(Serialize)]
    struct Inventory<'a> {
        schema_version: u32,
        store_format_version: u32,
        hmac_key_id: &'a str,
        next_hmac_key_id: &'a str,
        modules: &'a [CheckpointModuleHead],
        tombstones: &'a [CheckpointTombstone],
        operations: &'a [CheckpointOperation],
    }

    let bytes = match schema_version {
        LEGACY_CHECKPOINT_SCHEMA_VERSION => {
            ensure!(
                store_format_version == LEGACY_STORE_FORMAT_VERSION,
                "legacy checkpoint has an invalid store format"
            );
            serde_json::to_vec(&LegacyInventory {
                schema_version,
                hmac_key_id,
                next_hmac_key_id,
                modules,
                tombstones,
                operations,
            })?
        }
        CHECKPOINT_SCHEMA_VERSION => {
            ensure!(
                store_format_version == STORE_FORMAT_VERSION,
                "checkpoint has an invalid store format"
            );
            serde_json::to_vec(&Inventory {
                schema_version,
                store_format_version,
                hmac_key_id,
                next_hmac_key_id,
                modules,
                tombstones,
                operations,
            })?
        }
        _ => bail!("unsupported checkpoint schema"),
    };
    Ok(hex(&Sha256::digest(bytes)))
}

#[derive(Clone)]
#[cfg_attr(not(any(target_os = "android", test)), allow(dead_code))]
struct VerifiedManagerSeal {
    envelope: ManagerCheckpointEnvelope,
    payload: CheckpointPayload,
    seal_hash: String,
}

#[cfg_attr(not(any(target_os = "android", test)), allow(dead_code))]
pub fn manager_audit_seal_status(root: &Path) -> Result<ManagerAuditSealStatus> {
    if dashboard_store_uninitialized(root)? {
        return Ok(ManagerAuditSealStatus {
            configured: false,
            generation: None,
            seal_hash: None,
            inventory_hash: None,
            key_id: None,
        });
    }
    Ok(verified_audit_snapshot(root)?.seal_status)
}

fn manager_audit_seal_status_from(
    registry: Option<ManagerAuditAuthRegistry>,
    seal: Option<VerifiedManagerSeal>,
) -> ManagerAuditSealStatus {
    match seal {
        Some(seal) => ManagerAuditSealStatus {
            configured: true,
            generation: Some(seal.envelope.generation),
            seal_hash: Some(seal.seal_hash),
            inventory_hash: Some(seal.payload.inventory_hash),
            key_id: Some(seal.envelope.key_id),
        },
        None => ManagerAuditSealStatus {
            configured: false,
            generation: None,
            seal_hash: None,
            inventory_hash: None,
            key_id: registry.map(|registry| registry.key_id),
        },
    }
}

#[cfg_attr(not(any(target_os = "android", test)), allow(dead_code))]
pub fn commit_manager_audit_seal(
    root: &Path,
    encoded_envelope: &str,
) -> Result<ManagerAuditSealStatus> {
    let envelope_bytes = decode_hex(encoded_envelope)?;
    let envelope: ManagerCheckpointEnvelope = serde_json::from_slice(&envelope_bytes)
        .context("parse Manager audit checkpoint envelope")?;
    let envelope_hex = hex(&envelope_bytes);
    let seal_hash = hex(&Sha256::digest(&envelope_bytes));

    let _lock = AuditLock::acquire(root, false)?;
    let key = load_key(root, false)?;
    recover_operation_progress(root, &key)?;
    let registry = read_manager_auth_registry(root, &key)?
        .context("Manager audit authorization key is not configured")?;
    let payload = verify_manager_checkpoint_envelope(&envelope, &registry)?;
    let current = checkpoint_payload_readonly_unlocked(root, &key)?;
    ensure!(
        payload.inventory_hash == current.inventory_hash
            && payload.hmac_key_id == current.hmac_key_id
            && payload.next_hmac_key_id == current.next_hmac_key_id
            && payload.modules == current.modules
            && payload.tombstones == current.tombstones
            && payload.operations == current.operations,
        "Manager audit seal does not describe the current verified inventory"
    );

    if let Some(previous) = load_verified_manager_seal(root, &registry)? {
        if previous.seal_hash == seal_hash {
            complete_hmac_rotation(root, &key, &previous.payload, &previous.seal_hash)?;
            finalize_sealed_operation_trash(root, &previous.payload)?;
            return Ok(ManagerAuditSealStatus {
                configured: true,
                generation: Some(previous.envelope.generation),
                seal_hash: Some(previous.seal_hash),
                inventory_hash: Some(previous.payload.inventory_hash),
                key_id: Some(previous.envelope.key_id),
            });
        }
        ensure!(
            envelope.generation == previous.envelope.generation.saturating_add(1),
            "Manager audit seal generation is not the next expected value"
        );
        ensure_checkpoint_extends(
            root,
            &key,
            &previous.seal_hash,
            &previous.payload,
            &payload,
            &registry,
        )?;
    } else {
        for operation in &payload.operations {
            verify_checkpoint_operation_authorization(operation, &registry)?;
        }
    }

    atomic_write_json(
        &manager_seal_path(root),
        &StoredManagerSeal {
            envelope_hex,
            seal_hash: seal_hash.clone(),
        },
    )?;
    finalize_sealed_recovery_records(root, &payload)?;
    complete_hmac_rotation(root, &key, &payload, &seal_hash)?;
    finalize_sealed_operation_trash(root, &payload)?;
    Ok(ManagerAuditSealStatus {
        configured: true,
        generation: Some(envelope.generation),
        seal_hash: Some(seal_hash),
        inventory_hash: Some(payload.inventory_hash),
        key_id: Some(envelope.key_id),
    })
}

fn finalize_sealed_recovery_records(root: &Path, payload: &CheckpointPayload) -> Result<()> {
    for operation in &payload.operations {
        if operation.action != AuditAction::RecoverSealed
            || operation.state != AuditOperationState::Applied
        {
            continue;
        }
        for module_id in &operation.completed_targets {
            let path = sealed_recovery_path(root, module_id);
            if path.exists() {
                std::fs::remove_file(&path).context("finalize Manager-sealed audit recovery")?;
                sync_dir(path.parent().context("sealed recovery has no parent")?)?;
            }
        }
    }
    Ok(())
}

fn finalize_sealed_operation_trash(root: &Path, payload: &CheckpointPayload) -> Result<()> {
    for operation in &payload.operations {
        if !operation.action.descriptor().finalizes_operation_trash
            || operation.state == AuditOperationState::Applying
        {
            continue;
        }
        let trash = root.join(OPERATION_TRASH_DIR).join(&operation.operation_id);
        if trash.exists() {
            std::fs::remove_dir_all(&trash).with_context(|| {
                format!("finalize sealed audit cleanup {}", operation.operation_id)
            })?;
            sync_dir(trash.parent().context("operation trash has no parent")?)?;
        }
    }
    Ok(())
}

fn load_verified_manager_seal(
    root: &Path,
    registry: &ManagerAuditAuthRegistry,
) -> Result<Option<VerifiedManagerSeal>> {
    let path = manager_seal_path(root);
    if !path.exists() {
        return Ok(None);
    }
    let stored: StoredManagerSeal = read_json(&path)?;
    let envelope_bytes = decode_hex(&stored.envelope_hex)?;
    ensure!(
        stored.seal_hash == hex(&Sha256::digest(&envelope_bytes)),
        "Manager audit seal hash mismatch"
    );
    let envelope: ManagerCheckpointEnvelope = serde_json::from_slice(&envelope_bytes)
        .context("parse stored Manager audit checkpoint envelope")?;
    let payload = verify_manager_checkpoint_envelope(&envelope, registry)?;
    Ok(Some(VerifiedManagerSeal {
        envelope,
        payload,
        seal_hash: stored.seal_hash,
    }))
}

fn verified_sealed_event_hashes(
    root: &Path,
    module_id: &str,
    key: &[u8; 32],
) -> Result<Vec<String>> {
    let registry = read_manager_auth_registry(root, key)?;
    if registry.is_none() {
        ensure!(
            !manager_seal_path(root).exists(),
            "Manager audit seal exists without a registered Manager key"
        );
        return Ok(Vec::new());
    }
    let registry = registry.as_ref().expect("checked above");
    let Some(seal) = load_verified_manager_seal(root, registry)? else {
        return Ok(Vec::new());
    };
    let mut hashes = seal
        .payload
        .modules
        .iter()
        .find(|module| module.module_id == module_id)
        .map(|module| module.event_hashes.clone())
        .unwrap_or_default();
    if let Some(recovery) = read_sealed_recovery(root, module_id, key)?
        && recovery.seal_hash == seal.seal_hash
    {
        verify_sealed_recovery_record(&recovery, &seal, registry, root, key)?;
        let retained = usize::try_from(recovery.corrupted_from_sequence.saturating_sub(1))?;
        ensure!(
            retained <= hashes.len(),
            "sealed recovery boundary is outside the seal"
        );
        hashes.truncate(retained);
    }
    Ok(hashes)
}

fn sealed_recovery_path(root: &Path, module_id: &str) -> PathBuf {
    root.join(SEALED_RECOVERY_DIR)
        .join(format!("{}.json", module_dir_name(module_id)))
}

fn read_sealed_recovery(
    root: &Path,
    module_id: &str,
    key: &[u8; 32],
) -> Result<Option<SealedRecoveryRecord>> {
    let path = sealed_recovery_path(root, module_id);
    if !path.exists() {
        return Ok(None);
    }
    let authenticated: AuthenticatedRecord<SealedRecoveryRecord> = read_json(&path)?;
    verify_record(&authenticated.record, &authenticated.hmac_sha256, key)?;
    ensure!(
        authenticated.record.schema_version == SCHEMA_VERSION
            && authenticated.record.module_id == module_id,
        "invalid sealed recovery record"
    );
    Ok(Some(authenticated.record))
}

fn verify_sealed_recovery_record(
    recovery: &SealedRecoveryRecord,
    seal: &VerifiedManagerSeal,
    registry: &ManagerAuditAuthRegistry,
    root: &Path,
    key: &[u8; 32],
) -> Result<()> {
    ensure!(
        recovery.base_inventory_hash == seal.payload.inventory_hash,
        "sealed recovery is not bound to the active inventory"
    );
    let operation = read_operation(root, &recovery.operation_id, key)?
        .context("sealed recovery authorization operation is unavailable")?;
    ensure!(
        operation.action == AuditAction::RecoverSealed
            && operation.base_inventory_hash == seal.payload.inventory_hash
            && operation.targets == [recovery.module_id.as_str()],
        "sealed recovery operation identity mismatch"
    );
    let expected_arguments_hash = sealed_recovery_arguments_hash(
        &recovery.seal_hash,
        &recovery.base_inventory_hash,
        &SealedIntegrityFailure {
            module_id: recovery.module_id.clone(),
            corrupted_from_sequence: recovery.corrupted_from_sequence,
            cause: recovery.cause,
            reason: recovery.reason.clone(),
            unexpected_paths: recovery.unexpected_paths.clone(),
        },
    )?;
    ensure!(
        operation.arguments_hash == expected_arguments_hash,
        "sealed recovery boundary is not Manager-authorized"
    );
    verify_checkpoint_operation_authorization(&operation.checkpoint(), registry)
}

#[cfg_attr(not(any(target_os = "android", test)), allow(dead_code))]
pub fn sealed_integrity_status(root: &Path) -> Result<SealedIntegrityStatus> {
    let snapshot = verified_audit_snapshot(root)?;
    Ok(SealedIntegrityStatus {
        seal_hash: snapshot
            .seal_status
            .seal_hash
            .context("Manager audit seal is not configured")?,
        inventory_hash: snapshot
            .seal_status
            .inventory_hash
            .context("Manager audit seal inventory is unavailable")?,
        failures: snapshot.integrity_failures,
    })
}

pub fn verified_audit_snapshot(root: &Path) -> Result<VerifiedAuditSnapshot> {
    verified_audit_snapshot_with_progress(root, |_| Ok(()))
}

pub fn verified_audit_snapshot_with_progress(
    root: &Path,
    mut progress: impl FnMut(VerifiedAuditProgress) -> Result<()>,
) -> Result<VerifiedAuditSnapshot> {
    let _lock = AuditLock::acquire(root, false)?;
    let key = read_key(root)?;
    retry_verified_snapshot(
        || verified_audit_snapshot_once(root, &key, &mut progress),
        || std::thread::sleep(VERIFIED_SNAPSHOT_RETRY_DELAY),
    )
}

fn verified_audit_snapshot_once(
    root: &Path,
    key: &[u8; 32],
    progress: &mut impl FnMut(VerifiedAuditProgress) -> Result<()>,
) -> Result<VerifiedAuditSnapshot> {
    let revision_before =
        dashboard_store_revision(root).context("read audit revision before verified snapshot")?;
    verify_tombstones(root, key)?;

    let registry = read_manager_auth_registry(root, key)?;
    let seal = match &registry {
        Some(registry) => load_verified_manager_seal(root, registry)?,
        None => None,
    };
    let module_ids = if root.join("modules").exists() {
        audit_module_ids(&root.join("modules"))?
    } else {
        Vec::new()
    };
    let total_modules = module_ids.len();
    progress(VerifiedAuditProgress::Start { total_modules })?;
    let mut histories = Vec::with_capacity(total_modules);
    for (index, module_id) in module_ids.iter().enumerate() {
        histories.push(read_module_history_resilient_unlocked(
            root, module_id, key,
        )?);
        progress(VerifiedAuditProgress::Module {
            module_id: module_id.clone(),
            completed: index + 1,
            total_modules,
        })?;
    }
    progress(VerifiedAuditProgress::Checkpoint {
        completed: total_modules,
        total_modules,
    })?;
    let current_checkpoint = checkpoint_payload_readonly_unlocked(root, key);

    let (inventory_relation, checkpoint, integrity_failures) = match &seal {
        None => (
            AuditInventoryRelation::Unsealed,
            current_checkpoint?,
            Vec::new(),
        ),
        Some(seal) => {
            let integrity = sealed_integrity_status_with_snapshot_unlocked(
                root,
                key,
                &histories,
                current_checkpoint.as_ref().ok(),
            )?;
            match current_checkpoint {
                Ok(current)
                    if histories
                        .iter()
                        .all(|history| history.integrity_error.is_none()) =>
                {
                    if checkpoint_inventory_matches(&current, &seal.payload) {
                        ensure!(
                            integrity.failures.is_empty(),
                            "Manager-sealed inventory matches despite integrity failures"
                        );
                        (AuditInventoryRelation::SealedCurrent, current, Vec::new())
                    } else {
                        match registry.as_ref() {
                            Some(registry)
                                if ensure_checkpoint_extends(
                                    root,
                                    key,
                                    &seal.seal_hash,
                                    &seal.payload,
                                    &current,
                                    registry,
                                )
                                .is_ok() =>
                            {
                                (
                                    AuditInventoryRelation::AuthorizedTransition,
                                    current,
                                    Vec::new(),
                                )
                            }
                            _ if !integrity.failures.is_empty() => (
                                AuditInventoryRelation::SealedDamage,
                                seal.payload.clone(),
                                integrity.failures,
                            ),
                            Some(registry) => {
                                ensure_checkpoint_extends(
                                    root,
                                    key,
                                    &seal.seal_hash,
                                    &seal.payload,
                                    &current,
                                    registry,
                                )
                                .context(
                                    "current audit inventory is not an authorized transition",
                                )?;
                                unreachable!()
                            }
                            None => unreachable!("verified seal requires a Manager registry"),
                        }
                    }
                }
                Ok(_) | Err(_) if !integrity.failures.is_empty() => (
                    AuditInventoryRelation::SealedDamage,
                    seal.payload.clone(),
                    integrity.failures,
                ),
                Ok(_) => unreachable!("clean current checkpoint was handled above"),
                Err(error) => return Err(error).context("read current verified audit inventory"),
            }
        }
    };
    let seal_status = manager_audit_seal_status_from(registry.clone(), seal.clone());
    let authorization_status = ManagerAuditAuthStatus {
        configured: registry.is_some(),
        key_id: registry.map(|registry| registry.key_id),
        inventory_hash: checkpoint.inventory_hash.clone(),
    };
    let revision_after =
        dashboard_store_revision(root).context("read audit revision after verified snapshot")?;
    if revision_before != revision_after {
        return Err(AuditSnapshotChanged.into());
    }
    Ok(VerifiedAuditSnapshot {
        store_revision: revision_after,
        inventory_relation,
        histories,
        checkpoint,
        integrity_failures,
        seal_status,
        authorization_status,
    })
}

fn checkpoint_inventory_matches(left: &CheckpointPayload, right: &CheckpointPayload) -> bool {
    left.inventory_hash == right.inventory_hash
        && left.hmac_key_id == right.hmac_key_id
        && left.next_hmac_key_id == right.next_hmac_key_id
        && left.modules == right.modules
        && left.tombstones == right.tombstones
        && left.operations == right.operations
}

/// Verify the Manager seal and every module history against one locked audit
/// store snapshot. The revision guard retries transient direct filesystem
/// changes from writers that do not participate in the audit lock protocol.
#[cfg(test)]
pub fn containment_inventory_snapshot(
    root: &Path,
) -> Result<(SealedIntegrityStatus, Vec<ModuleAuditStatus>)> {
    let snapshot = verified_audit_snapshot(root)?;
    let seal_hash = snapshot
        .seal_status
        .seal_hash
        .context("Manager audit seal is not configured")?;
    let inventory_hash = snapshot
        .seal_status
        .inventory_hash
        .context("Manager audit seal inventory is unavailable")?;
    Ok((
        SealedIntegrityStatus {
            seal_hash,
            inventory_hash,
            failures: snapshot.integrity_failures,
        },
        snapshot
            .histories
            .into_iter()
            .map(|history| history.status)
            .collect(),
    ))
}

fn retry_verified_snapshot<T>(
    mut capture: impl FnMut() -> Result<T>,
    mut wait: impl FnMut(),
) -> Result<T> {
    for attempt in 1..=VERIFIED_SNAPSHOT_ATTEMPTS {
        match capture() {
            Ok(snapshot) => return Ok(snapshot),
            Err(error) if error.is::<AuditSnapshotChanged>() => {
                if attempt == VERIFIED_SNAPSHOT_ATTEMPTS {
                    return Err(error).with_context(|| {
                        format!(
                            "cannot obtain a stable module audit snapshot after {VERIFIED_SNAPSHOT_ATTEMPTS} attempts"
                        )
                    });
                }
                wait();
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!("containment snapshot attempts must be nonzero")
}

/// Return a dashboard checkpoint without hiding Manager-sealed damage.
///
/// A damaged sealed history cannot produce a current checkpoint. In that case
/// the verified Manager-sealed payload remains the only trusted inventory base
/// and is returned solely to support fail-closed incident recovery.
#[cfg(test)]
pub fn dashboard_checkpoint_snapshot(root: &Path) -> Result<DashboardCheckpointSnapshot> {
    let snapshot = verified_audit_snapshot(root)?;
    Ok(DashboardCheckpointSnapshot {
        checkpoint: snapshot.checkpoint,
        integrity_failures: snapshot.integrity_failures,
    })
}

fn sealed_integrity_status_unlocked(root: &Path, key: &[u8; 32]) -> Result<SealedIntegrityStatus> {
    sealed_integrity_status_with_snapshot_unlocked(root, key, &[], None)
}

fn sealed_integrity_status_with_snapshot_unlocked(
    root: &Path,
    key: &[u8; 32],
    histories: &[ModuleAuditHistory],
    current_checkpoint: Option<&CheckpointPayload>,
) -> Result<SealedIntegrityStatus> {
    let registry = read_manager_auth_registry(root, key)?
        .context("Manager audit authorization key is not configured")?;
    let seal = load_verified_manager_seal(root, &registry)?
        .context("Manager audit seal is not configured")?;
    let mut failures = Vec::new();
    for module in &seal.payload.modules {
        let verified_history = histories
            .iter()
            .find(|history| history.status.module_id == module.module_id);
        if let Some(recovery) = read_sealed_recovery(root, &module.module_id, key)?
            && recovery.seal_hash == seal.seal_hash
        {
            verify_sealed_recovery_record(&recovery, &seal, &registry, root, key)?;
            let verified_chain = match verified_history {
                Some(history) if history.integrity_error.is_none() => Ok(()),
                _ => verify_chain(root, &module.module_id, key, false).map(|_| ()),
            };
            match verified_chain {
                Ok(_) => continue,
                Err(error) => {
                    if let Some(failure) = diagnose_sealed_module(root, module)? {
                        failures.push(failure);
                        continue;
                    }
                    return Err(error)
                        .context("recovered audit chain failed without sealed damage");
                }
            }
        }
        let sealed_prefix_verified = verified_history
            .is_some_and(|history| history.integrity_error.is_none())
            && current_checkpoint
                .and_then(|checkpoint| {
                    checkpoint
                        .modules
                        .iter()
                        .find(|current| current.module_id == module.module_id)
                })
                .is_some_and(|current| current.event_hashes.starts_with(&module.event_hashes));
        if sealed_prefix_verified {
            continue;
        }
        if let Some(failure) = diagnose_sealed_module(root, module)? {
            failures.push(failure);
        }
    }
    failures.sort_by(|left, right| left.module_id.cmp(&right.module_id));
    Ok(SealedIntegrityStatus {
        seal_hash: seal.seal_hash,
        inventory_hash: seal.payload.inventory_hash,
        failures,
    })
}

fn diagnose_sealed_module(
    root: &Path,
    module: &CheckpointModuleHead,
) -> Result<Option<SealedIntegrityFailure>> {
    Ok(verified_sealed_prefix(root, module)?.1)
}

fn verified_sealed_prefix(
    root: &Path,
    module: &CheckpointModuleHead,
) -> Result<(Vec<AuthenticatedEvent>, Option<SealedIntegrityFailure>)> {
    let events_dir = module_path(root, &module.module_id).join("events");
    let unexpected = if events_dir.is_dir() {
        let (_, unexpected) = audit_event_paths(&events_dir)?;
        unexpected
    } else {
        Vec::new()
    };
    let unexpected_paths = unexpected
        .iter()
        .map(|path| path.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    let mut valid = Vec::new();
    for (index, sealed_hash) in module.event_hashes.iter().enumerate() {
        let sequence = u64::try_from(index)?.saturating_add(1);
        let path = event_path(root, &module.module_id, sequence);
        let result = if path.is_file() {
            verify_event_file(
                &path,
                &module.module_id,
                sequence,
                &valid,
                &[0_u8; 32],
                Some(sealed_hash),
            )
        } else {
            Err(anyhow::anyhow!("Manager-sealed audit event is missing"))
        };
        match result {
            Ok(event) => valid.push(event),
            Err(error) => {
                return Ok((
                    valid,
                    Some(SealedIntegrityFailure {
                        module_id: module.module_id.clone(),
                        corrupted_from_sequence: sequence,
                        cause: if path.is_file() {
                            AuditIncidentCause::AuditEventInvalid
                        } else {
                            AuditIncidentCause::AuditEventMissing
                        },
                        reason: format!("{error:#}"),
                        unexpected_paths,
                    }),
                ));
            }
        }
    }
    let failure = (!unexpected_paths.is_empty()).then(|| {
        let reason = if unexpected_paths.len() == 1 {
            format!(
                "audit event directory contains unexpected entry {}",
                unexpected_paths[0]
            )
        } else {
            format!(
                "audit event directory contains unexpected entries: {}",
                unexpected_paths.join(", ")
            )
        };
        SealedIntegrityFailure {
            module_id: module.module_id.clone(),
            corrupted_from_sequence: u64::try_from(module.event_hashes.len())
                .unwrap_or(u64::MAX)
                .saturating_add(1),
            cause: AuditIncidentCause::UnexpectedAuditPath,
            reason,
            unexpected_paths,
        }
    });
    Ok((valid, failure))
}

#[cfg_attr(not(target_os = "android"), allow(dead_code))]
fn persistent_paths_from_events(events: &[AuthenticatedEvent]) -> Vec<String> {
    let mut paths = std::collections::BTreeSet::new();
    for entry in events {
        let report = match &entry.event.kind {
            AuditEventKind::InstallAccepted { report, .. }
            | AuditEventKind::InstalledRescan { report, .. } => Some(report),
            _ => None,
        };
        if let Some(report) = report {
            paths.extend(
                report
                    .findings
                    .iter()
                    .filter(|finding| finding.rule_id == "KSU-AUDIT-PERSIST-001")
                    .map(|finding| finding.path.clone()),
            );
        }
    }
    paths.into_iter().collect()
}

/// Builds a fail-closed persistent-script plan only from events whose hashes are
/// anchored in the active Manager seal. An empty verified prefix means ownership
/// cannot be recovered and callers must use exclusion against other trusted logs.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub fn persistent_script_containment_plans(
    root: &Path,
) -> Result<Vec<PersistentScriptContainmentPlan>> {
    let _lock = AuditLock::acquire(root, false)?;
    let key = read_key(root)?;
    let registry = read_manager_auth_registry(root, &key)?
        .context("Manager audit authorization key is not configured")?;
    let seal = load_verified_manager_seal(root, &registry)?
        .context("Manager audit seal is not configured")?;
    let mut plans = Vec::new();
    for module in &seal.payload.modules {
        let (trusted, failure) = verified_sealed_prefix(root, module)?;
        let Some(_failure) = failure else {
            continue;
        };
        plans.push(PersistentScriptContainmentPlan {
            module_id: module.module_id.clone(),
            paths: persistent_paths_from_events(&trusted),
            infer_unattributed: trusted.is_empty(),
        });
    }
    Ok(plans)
}

/// Returns persistent paths attributable to intact Manager-sealed histories.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub fn trusted_persistent_script_paths(root: &Path) -> Result<Vec<String>> {
    let _lock = AuditLock::acquire(root, false)?;
    let key = read_key(root)?;
    let registry = read_manager_auth_registry(root, &key)?
        .context("Manager audit authorization key is not configured")?;
    let seal = load_verified_manager_seal(root, &registry)?
        .context("Manager audit seal is not configured")?;
    let mut paths = std::collections::BTreeSet::new();
    for module in &seal.payload.modules {
        let (events, failure) = verified_sealed_prefix(root, module)?;
        if failure.is_some() {
            continue;
        }
        paths.extend(persistent_paths_from_events(&events));
    }
    Ok(paths.into_iter().collect())
}

#[cfg_attr(not(target_os = "android"), allow(dead_code))]
fn persistent_quarantine_record_path(root: &Path, module_id: &str) -> PathBuf {
    root.join(CONTAINMENT_DIR)
        .join(module_dir_name(module_id))
        .join("persistent.json")
}

fn persistent_containment_result_path(root: &Path, module_id: &str) -> PathBuf {
    root.join(CONTAINMENT_DIR)
        .join(module_dir_name(module_id))
        .join("persistent-result.json")
}

fn read_persistent_containment_result(
    root: &Path,
    module_id: &str,
    key: &[u8; 32],
) -> Result<PersistentContainmentResultRecord> {
    let path = persistent_containment_result_path(root, module_id);
    if !path.exists() {
        return Ok(PersistentContainmentResultRecord::default());
    }
    let authenticated: AuthenticatedRecord<PersistentContainmentResultRecord> = read_json(&path)?;
    verify_record(&authenticated.record, &authenticated.hmac_sha256, key)?;
    ensure!(
        authenticated.record.module_id == module_id,
        "persistent containment result module id mismatch"
    );
    Ok(authenticated.record)
}

#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub fn record_persistent_containment_result(
    root: &Path,
    module_id: &str,
    uncertain_ownership: bool,
    quarantined_paths: &[String],
    failures: &[String],
) -> Result<()> {
    validate_module_id(module_id)?;
    let _lock = AuditLock::acquire(root, true)?;
    let key = load_key(root, false)?;
    let path = persistent_containment_result_path(root, module_id);
    if path.exists() {
        let authenticated: AuthenticatedRecord<PersistentContainmentResultRecord> =
            read_json(&path)?;
        verify_record(&authenticated.record, &authenticated.hmac_sha256, &key)?;
        ensure!(
            authenticated.record.module_id == module_id,
            "persistent containment result module id mismatch"
        );
    }
    let mut quarantined_paths = quarantined_paths.to_vec();
    quarantined_paths.sort();
    quarantined_paths.dedup();
    let mut failures = failures.to_vec();
    failures.sort();
    failures.dedup();
    write_record(
        &path,
        PersistentContainmentResultRecord {
            schema_version: SCHEMA_VERSION,
            module_id: module_id.to_owned(),
            uncertain_ownership,
            quarantined_paths,
            failures,
            updated_at_unix_seconds: now(),
        },
        &key,
    )
}

fn read_persistent_quarantine_summary(
    root: &Path,
    module_id: &str,
    key: &[u8; 32],
) -> Result<(usize, Option<PersistentScriptOwnership>)> {
    let path = persistent_quarantine_record_path(root, module_id);
    if !path.exists() {
        return Ok((0, None));
    }
    let authenticated: AuthenticatedRecord<PersistentQuarantineRecord> = read_json(&path)?;
    verify_record(&authenticated.record, &authenticated.hmac_sha256, key)?;
    ensure!(
        authenticated.record.module_id == module_id,
        "containment module id mismatch"
    );
    let count = authenticated.record.completed_paths.len();
    Ok((
        count,
        (count > 0).then_some(if authenticated.record.uncertain_ownership {
            PersistentScriptOwnership::Uncertain
        } else {
            PersistentScriptOwnership::Attributed
        }),
    ))
}

fn module_containment_record_path(root: &Path, module_id: &str) -> PathBuf {
    root.join(CONTAINMENT_DIR)
        .join(module_dir_name(module_id))
        .join("state.json")
}

fn read_containment_state(
    root: &Path,
    module_id: &str,
    key: &[u8; 32],
) -> Result<Option<ContainmentState>> {
    let path = module_containment_record_path(root, module_id);
    if !path.exists() {
        return Ok(None);
    }
    let authenticated: AuthenticatedRecord<ModuleContainmentRecord> = read_json(&path)?;
    verify_record(&authenticated.record, &authenticated.hmac_sha256, key)?;
    ensure!(
        authenticated.record.module_id == module_id,
        "containment module id mismatch"
    );
    Ok(Some(authenticated.record.state))
}

/// Clear execution state only after secure removal has durably ended the old
/// module instance. Audit events and persistent-script evidence remain intact.
fn clear_completed_containment_state(root: &Path, module_id: &str, key: &[u8; 32]) -> Result<()> {
    let Some(state) = read_containment_state(root, module_id, key)? else {
        return Ok(());
    };
    if state != ContainmentState::Contained
        || !secure_removal_ended_current_instance(root, module_id, key)?
    {
        return Ok(());
    }
    remove_containment_state(root, module_id)
}

fn secure_removal_ended_current_instance(
    root: &Path,
    module_id: &str,
    key: &[u8; 32],
) -> Result<bool> {
    let chain = verify_chain(root, module_id, key, true)?;
    let last_install = chain
        .events
        .iter()
        .filter_map(|entry| match entry.event.kind {
            AuditEventKind::InstallAccepted { .. } => Some(entry.event.sequence),
            _ => None,
        })
        .max()
        .unwrap_or(0);
    let last_secure_removal = chain
        .events
        .iter()
        .filter_map(|entry| match entry.event.kind {
            AuditEventKind::SecureRemovalCompleted { .. } => Some(entry.event.sequence),
            _ => None,
        })
        .max()
        .unwrap_or(0);
    Ok(last_secure_removal > last_install)
}

fn remove_containment_state(root: &Path, module_id: &str) -> Result<()> {
    let path = module_containment_record_path(root, module_id);
    std::fs::remove_file(&path)
        .with_context(|| format!("clear completed containment state for {module_id}"))?;
    sync_dir(path.parent().context("containment state has no parent")?)
}

#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub fn set_containment_state(root: &Path, module_id: &str, state: ContainmentState) -> Result<()> {
    validate_module_id(module_id)?;
    let _lock = AuditLock::acquire(root, true)?;
    let key = load_key(root, false)?;
    let existing = read_containment_state(root, module_id, &key)?;
    let state = match (existing, state) {
        (Some(ContainmentState::Contained), ContainmentState::PendingReboot) => {
            ContainmentState::Contained
        }
        (Some(ContainmentState::PersistentScriptsIncomplete), ContainmentState::PendingReboot) => {
            ContainmentState::PersistentScriptsIncomplete
        }
        (_, requested) => requested,
    };
    let completed_removal_can_release = existing.is_some()
        && state == ContainmentState::Contained
        && secure_removal_ended_current_instance(root, module_id, &key).unwrap_or(false);
    if completed_removal_can_release {
        return remove_containment_state(root, module_id);
    }
    if existing == Some(state) {
        return Ok(());
    }
    write_record(
        &module_containment_record_path(root, module_id),
        ModuleContainmentRecord {
            schema_version: SCHEMA_VERSION,
            module_id: module_id.to_owned(),
            state,
            updated_at_unix_seconds: now(),
        },
        &key,
    )
}

#[cfg_attr(not(target_os = "android"), allow(dead_code))]
fn persistent_quarantine_destination(
    root: &Path,
    module_id: &str,
    source: &Path,
) -> Result<PathBuf> {
    const ROOTS: &[&str] = &[
        "/data/adb/service.d",
        "/data/adb/boot-completed.d",
        "/data/adb/bootcompleted.d",
    ];
    let parent = source.parent().context("persistent script has no parent")?;
    let root_index = ROOTS
        .iter()
        .position(|candidate| parent == Path::new(candidate))
        .context("persistent script is outside an approved startup directory")?;
    let name = source
        .file_name()
        .context("persistent script has no file name")?;
    Ok(root
        .join(CONTAINMENT_DIR)
        .join(module_dir_name(module_id))
        .join("persistent")
        .join(root_index.to_string())
        .join(name))
}

/// Reversibly quarantines startup scripts and authenticates the move journal.
/// Re-running the operation resumes any move interrupted after the plan commit.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub fn quarantine_persistent_scripts(
    root: &Path,
    module_id: &str,
    paths: &[String],
    uncertain_ownership: bool,
) -> Result<PersistentScriptQuarantineOutcome> {
    validate_module_id(module_id)?;
    quarantine_persistent_scripts_inner(root, module_id, paths, uncertain_ownership)
}

fn quarantine_persistent_scripts_inner(
    root: &Path,
    record_id: &str,
    paths: &[String],
    uncertain_ownership: bool,
) -> Result<PersistentScriptQuarantineOutcome> {
    let _lock = AuditLock::acquire(root, true)?;
    let key = load_key(root, false)?;
    let record_path = persistent_quarantine_record_path(root, record_id);
    let mut record = if record_path.exists() {
        let authenticated: AuthenticatedRecord<PersistentQuarantineRecord> =
            read_json(&record_path)?;
        verify_record(&authenticated.record, &authenticated.hmac_sha256, &key)?;
        authenticated.record
    } else {
        PersistentQuarantineRecord {
            schema_version: SCHEMA_VERSION,
            module_id: record_id.to_owned(),
            uncertain_ownership,
            planned_paths: Vec::new(),
            completed_paths: Vec::new(),
            updated_at_unix_seconds: now(),
        }
    };
    ensure!(
        record.module_id == record_id,
        "containment module id mismatch"
    );
    record.uncertain_ownership |= uncertain_ownership;
    let mut failures = Vec::new();
    for path in paths {
        let source = Path::new(path);
        if let Err(error) = persistent_quarantine_destination(root, record_id, source) {
            failures.push(format!("reject persistent startup path {path}: {error:#}"));
            continue;
        }
        if !source.exists() {
            continue;
        }
        if !record.planned_paths.contains(path) {
            record.planned_paths.push(path.clone());
        }
    }
    record.planned_paths.sort();
    record.updated_at_unix_seconds = now();
    write_record(&record_path, record.clone(), &key)?;

    for path in record.planned_paths.clone() {
        if record.completed_paths.contains(&path) {
            continue;
        }
        let source = Path::new(&path);
        let destination = persistent_quarantine_destination(root, record_id, source)?;
        let moved = (|| -> Result<()> {
            if source.exists() {
                let metadata = std::fs::symlink_metadata(source)?;
                ensure!(
                    metadata.file_type().is_file(),
                    "refuse to quarantine non-regular startup file {path}"
                );
                ensure_dir(
                    destination
                        .parent()
                        .context("quarantine destination has no parent")?,
                )?;
                ensure!(
                    !destination.exists(),
                    "persistent quarantine destination already exists"
                );
                std::fs::rename(source, &destination)
                    .with_context(|| format!("quarantine persistent startup script {path}"))?;
            } else {
                ensure!(
                    destination.is_file(),
                    "planned persistent script disappeared: {path}"
                );
            }
            Ok(())
        })();
        if let Err(error) = moved {
            failures.push(format!("{path}: {error:#}"));
            continue;
        }
        record.completed_paths.push(path);
        record.completed_paths.sort();
        record.updated_at_unix_seconds = now();
        write_record(&record_path, record.clone(), &key)?;
    }
    Ok(PersistentScriptQuarantineOutcome {
        completed_paths: record.completed_paths,
        failures,
    })
}

/// Quarantines startup scripts whose owner cannot be established from any
/// intact Manager-sealed history. The reserved incident bucket deliberately is
/// not the identity of an installed module.
#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub fn quarantine_unattributed_persistent_scripts(
    root: &Path,
    paths: &[String],
) -> Result<PersistentScriptQuarantineOutcome> {
    quarantine_persistent_scripts_inner(
        root,
        "@global/unattributed-persistent-scripts",
        paths,
        true,
    )
}

fn verify_manager_checkpoint_envelope(
    envelope: &ManagerCheckpointEnvelope,
    registry: &ManagerAuditAuthRegistry,
) -> Result<CheckpointPayload> {
    ensure!(
        envelope.schema_version == MANAGER_SEAL_SCHEMA_VERSION,
        "unsupported Manager audit seal schema"
    );
    ensure!(
        envelope.generation > 0,
        "invalid Manager audit seal generation"
    );
    ensure!(
        matches!(
            envelope.key_backend.as_str(),
            "android_keystore" | "software_file"
        ),
        "invalid Manager audit seal key backend"
    );
    ensure!(
        matches!(
            envelope.key_protection.as_str(),
            "hardware" | "degraded" | "emergency"
        ),
        "invalid Manager audit seal protection level"
    );
    ensure!(
        envelope.key_id == registry.key_id,
        "Manager audit seal key identity mismatch"
    );
    let payload_bytes =
        decode_base64(&envelope.payload).context("decode Manager audit seal payload")?;
    let payload: CheckpointPayload =
        serde_json::from_slice(&payload_bytes).context("parse Manager audit seal payload")?;
    ensure!(
        matches!(
            (payload.schema_version, payload.store_format_version),
            (
                LEGACY_CHECKPOINT_SCHEMA_VERSION,
                LEGACY_STORE_FORMAT_VERSION
            ) | (CHECKPOINT_SCHEMA_VERSION, STORE_FORMAT_VERSION)
        ),
        "unsupported Manager audit seal payload schema"
    );
    validate_sha256_hex(&payload.hmac_key_id, "HMAC key id")?;
    validate_sha256_hex(&payload.next_hmac_key_id, "next HMAC key id")?;
    validate_sha256_hex(&payload.inventory_hash, "inventory hash")?;
    for operation in &payload.operations {
        validate_checkpoint_operation(operation)?;
    }
    ensure!(
        checkpoint_inventory_hash(
            payload.schema_version,
            payload.store_format_version,
            &payload.hmac_key_id,
            &payload.next_hmac_key_id,
            &payload.modules,
            &payload.tombstones,
            &payload.operations,
        )? == payload.inventory_hash,
        "Manager audit seal inventory hash mismatch"
    );

    let public_key = decode_hex(&registry.public_key_hex)?;
    let verifying_key =
        VerifyingKey::from_sec1_bytes(&public_key).context("invalid registered Manager key")?;
    let signature_bytes =
        decode_base64(&envelope.signature).context("decode Manager audit seal signature")?;
    let signature =
        Signature::from_der(&signature_bytes).context("invalid Manager audit seal signature")?;
    let signable = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        envelope.schema_version,
        envelope.generation,
        envelope.key_backend,
        envelope.key_protection,
        envelope.key_id,
        envelope.payload,
    );
    verifying_key
        .verify(signable.as_bytes(), &signature)
        .context("Manager audit seal signature rejected")?;
    Ok(payload)
}

fn verify_checkpoint_operation_authorization(
    operation: &CheckpointOperation,
    registry: &ManagerAuditAuthRegistry,
) -> Result<()> {
    let token_bytes = decode_hex(&operation.authorization_hex)?;
    ensure!(
        hex(&Sha256::digest(&token_bytes)) == operation.operation_id,
        "audit operation authorization hash mismatch"
    );
    let token: SignedAuditAuthorization = serde_json::from_slice(&token_bytes)
        .context("parse checkpoint audit operation authorization")?;
    ensure!(
        token.schema_version == MANAGER_AUTH_SCHEMA_VERSION
            && token.action == operation.action
            && token.inventory_hash == operation.base_inventory_hash
            && token.arguments_hash == operation.arguments_hash
            && token.key_id == registry.key_id,
        "checkpoint audit operation authorization mismatch"
    );
    validate_sha256_hex(&token.challenge_id, "challenge id")?;
    let public_key = decode_hex(&registry.public_key_hex)?;
    let verifying_key =
        VerifyingKey::from_sec1_bytes(&public_key).context("invalid registered Manager key")?;
    let signature = Signature::from_der(&decode_hex(&token.signature_der_hex)?)
        .context("invalid checkpoint operation signature")?;
    verifying_key
        .verify(
            audit_authorization_message(
                token.action,
                &token.inventory_hash,
                &token.arguments_hash,
                &token.key_id,
                &token.challenge_id,
                token.created_at_unix_seconds,
            )
            .as_bytes(),
            &signature,
        )
        .context("checkpoint audit operation authorization rejected")
}

#[cfg_attr(not(any(target_os = "android", test)), allow(dead_code))]
fn ensure_checkpoint_extends(
    root: &Path,
    key: &[u8; 32],
    previous_seal_hash: &str,
    previous: &CheckpointPayload,
    current: &CheckpointPayload,
    registry: &ManagerAuditAuthRegistry,
) -> Result<()> {
    ensure!(
        (previous.schema_version == current.schema_version
            && previous.store_format_version == current.store_format_version)
            || (previous.schema_version == LEGACY_CHECKPOINT_SCHEMA_VERSION
                && previous.store_format_version == LEGACY_STORE_FORMAT_VERSION
                && current.schema_version == CHECKPOINT_SCHEMA_VERSION
                && current.store_format_version == STORE_FORMAT_VERSION),
        "Manager audit store format changed unexpectedly"
    );
    let same_hmac_key = previous.hmac_key_id == current.hmac_key_id;
    let authorized_hmac_rotation = previous.next_hmac_key_id == current.hmac_key_id;
    ensure!(
        same_hmac_key || authorized_hmac_rotation,
        "Manager audit seal HMAC key identity changed unexpectedly"
    );
    ensure!(
        !same_hmac_key
            || previous.next_hmac_key_id == current.next_hmac_key_id
            || previous.modules != current.modules
            || previous.tombstones != current.tombstones
            || previous.operations != current.operations,
        "pending HMAC key changed without completing its sealed rotation"
    );
    for old_tombstone in &previous.tombstones {
        ensure!(
            current.tombstones.contains(old_tombstone),
            "Manager audit seal lost an authenticated tombstone"
        );
    }
    for old_module in &previous.modules {
        if let Some(new_module) = current
            .modules
            .iter()
            .find(|module| module.module_id == old_module.module_id)
        {
            let extends_prefix = new_module
                .event_hashes
                .starts_with(&old_module.event_hashes);
            if !extends_prefix {
                let recovery = read_sealed_recovery(root, &old_module.module_id, key)?
                    .context("Manager audit history changed without sealed recovery evidence")?;
                ensure!(
                    recovery.seal_hash == previous_seal_hash
                        && recovery.base_inventory_hash == previous.inventory_hash,
                    "sealed recovery is not bound to the previous Manager seal"
                );
                let operation = current
                    .operations
                    .iter()
                    .find(|operation| operation.operation_id == recovery.operation_id)
                    .context("sealed recovery operation is missing from the checkpoint")?;
                ensure!(
                    operation.action == AuditAction::RecoverSealed
                        && operation.targets == [old_module.module_id.as_str()]
                        && operation.completed_targets == operation.targets
                        && operation.state == AuditOperationState::Applied,
                    "sealed recovery operation is incomplete"
                );
                verify_checkpoint_operation_authorization(operation, registry)?;
                let retained = usize::try_from(recovery.corrupted_from_sequence.saturating_sub(1))?;
                ensure!(
                    retained < old_module.event_hashes.len()
                        && new_module.event_hashes.len() == retained.saturating_add(1)
                        && new_module.event_hashes[..retained]
                            == old_module.event_hashes[..retained]
                        && new_module.high_risk,
                    "sealed recovery did not preserve the verified prefix and incident"
                );
            }
            ensure!(
                !old_module.high_risk || new_module.high_risk,
                "Manager audit seal attempted to clear a high-risk state: {}",
                old_module.module_id
            );
            continue;
        }
        let compacted = current.tombstones.iter().any(|tombstone| {
            tombstone.module_id == old_module.module_id
                && tombstone.previous_event_count >= old_module.event_hashes.len()
                && tombstone
                    .previous_event_hashes
                    .starts_with(&old_module.event_hashes)
                && (!old_module.high_risk || tombstone.had_integrity_incident)
        });
        ensure!(
            compacted,
            "Manager audit history disappeared without a matching tombstone: {}",
            old_module.module_id
        );
        let authenticated_tombstones = verified_tombstones(root, key)?;
        let authorized_prune = current.operations.iter().any(|operation| {
            operation.action == AuditAction::Prune
                && operation.base_inventory_hash == previous.inventory_hash
                && operation.state == AuditOperationState::Applied
                && operation.targets.contains(&old_module.module_id)
                && operation.completed_targets.contains(&old_module.module_id)
                && authenticated_tombstones.iter().any(|tombstone| {
                    tombstone.module_id == old_module.module_id
                        && tombstone.reason == format!("user_cleanup:{}", operation.operation_id)
                })
        });
        ensure!(
            authorized_prune,
            "Manager audit history disappeared without an authorized cleanup: {}",
            old_module.module_id
        );
    }
    for new_module in &current.modules {
        if previous
            .modules
            .iter()
            .any(|module| module.module_id == new_module.module_id)
        {
            continue;
        }
        ensure!(
            !current.tombstones.iter().any(|tombstone| {
                tombstone.module_id == new_module.module_id
                    && new_module
                        .event_hashes
                        .starts_with(&tombstone.previous_event_hashes)
            }),
            "compacted audit history was replayed as an active module: {}",
            new_module.module_id
        );
    }
    for old_operation in &previous.operations {
        let current_operation = current
            .operations
            .iter()
            .find(|operation| operation.operation_id == old_operation.operation_id)
            .with_context(|| {
                format!(
                    "Manager audit operation disappeared: {}",
                    old_operation.operation_id
                )
            })?;
        ensure_operation_extends(old_operation, current_operation)?;
    }
    for operation in &current.operations {
        validate_checkpoint_operation(operation)?;
        if !previous
            .operations
            .iter()
            .any(|previous| previous.operation_id == operation.operation_id)
        {
            verify_checkpoint_operation_authorization(operation, registry)?;
            ensure!(
                operation.base_inventory_hash == previous.inventory_hash,
                "new audit operation is not bound to the previous sealed inventory"
            );
        }
    }
    Ok(())
}

fn validate_checkpoint_operation(operation: &CheckpointOperation) -> Result<()> {
    validate_sha256_hex(&operation.operation_id, "operation id")?;
    validate_sha256_hex(
        &operation.base_inventory_hash,
        "operation base inventory hash",
    )?;
    validate_sha256_hex(&operation.arguments_hash, "operation arguments hash")?;
    ensure!(
        !operation.authorization_hex.is_empty()
            && operation.authorization_hex.len() <= 64 * 1024
            && operation
                .authorization_hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit()),
        "invalid checkpoint audit operation authorization"
    );
    ensure!(
        operation.targets.windows(2).all(|pair| pair[0] < pair[1])
            && operation
                .completed_targets
                .windows(2)
                .all(|pair| pair[0] < pair[1])
            && operation
                .completed_targets
                .iter()
                .all(|target| operation.targets.contains(target)),
        "non-canonical checkpoint audit operation"
    );
    ensure!(
        operation.state != AuditOperationState::Applied
            || operation.completed_targets == operation.targets,
        "applied checkpoint audit operation is incomplete"
    );
    ensure!(
        (operation.state == AuditOperationState::Interrupted) == operation.error.is_some(),
        "checkpoint audit operation interruption state is inconsistent"
    );
    ensure!(
        operation
            .error
            .as_ref()
            .is_none_or(|error| !error.is_empty() && error.len() <= 4096),
        "invalid checkpoint audit operation error"
    );
    Ok(())
}

fn ensure_operation_extends(
    previous: &CheckpointOperation,
    current: &CheckpointOperation,
) -> Result<()> {
    ensure!(
        previous.operation_id == current.operation_id
            && previous.action == current.action
            && previous.base_inventory_hash == current.base_inventory_hash
            && previous.arguments_hash == current.arguments_hash
            && previous.authorization_hex == current.authorization_hex
            && previous.targets == current.targets,
        "audit operation identity changed"
    );
    ensure!(
        current
            .completed_targets
            .starts_with(&previous.completed_targets),
        "audit operation progress was rolled back: {}",
        previous.operation_id
    );
    ensure!(
        previous.state == AuditOperationState::Applying || current.state == previous.state,
        "terminal audit operation changed state: {}",
        previous.operation_id
    );
    ensure!(
        previous.state == AuditOperationState::Applying || current.error == previous.error,
        "terminal audit operation error changed: {}",
        previous.operation_id
    );
    Ok(())
}

#[cfg_attr(not(any(target_os = "android", test)), allow(dead_code))]
pub fn manager_audit_auth_status(root: &Path) -> Result<ManagerAuditAuthStatus> {
    Ok(verified_audit_snapshot(root)?.authorization_status)
}

#[cfg_attr(not(target_os = "android"), allow(dead_code))]
pub fn manager_audit_auth_status_for_inventory(
    root: &Path,
    inventory_hash: &str,
) -> Result<ManagerAuditAuthStatus> {
    validate_sha256_hex(inventory_hash, "inventory hash")?;
    let _lock = AuditLock::acquire(root, false)?;
    let key = read_key(root)?;
    let registry = read_manager_auth_registry(root, &key)?;
    Ok(ManagerAuditAuthStatus {
        configured: registry.is_some(),
        key_id: registry.map(|registry| registry.key_id),
        inventory_hash: inventory_hash.to_owned(),
    })
}

#[cfg_attr(not(any(target_os = "android", test)), allow(dead_code))]
pub fn register_manager_audit_auth_key(
    root: &Path,
    public_key_hex: &str,
    allow_recovery: bool,
) -> Result<ManagerAuditAuthStatus> {
    let public_key = decode_hex(public_key_hex)?;
    ensure!(
        public_key.len() == 65 && public_key.first() == Some(&4),
        "Manager audit authorization key must be an uncompressed P-256 point"
    );
    VerifyingKey::from_sec1_bytes(&public_key).context("invalid Manager audit public key")?;
    let key_id = hex(&Sha256::digest(&public_key));

    let lock = AuditLock::acquire(root, true)?;
    let hmac_key = load_key(root, true)?;
    let current = read_manager_auth_registry(root, &hmac_key);
    match current {
        Ok(Some(current)) if current.key_id == key_id => {}
        Ok(Some(_)) | Err(_) => {
            ensure!(
                allow_recovery,
                "Manager audit authorization key mismatch; boot KernelSU safe mode to recover"
            );
            write_record(
                &manager_auth_path(root),
                ManagerAuditAuthRegistry {
                    schema_version: MANAGER_AUTH_SCHEMA_VERSION,
                    public_key_hex: public_key_hex.to_owned(),
                    key_id,
                },
                &hmac_key,
            )?;
        }
        Ok(None) => {
            write_record(
                &manager_auth_path(root),
                ManagerAuditAuthRegistry {
                    schema_version: MANAGER_AUTH_SCHEMA_VERSION,
                    public_key_hex: public_key_hex.to_owned(),
                    key_id,
                },
                &hmac_key,
            )?;
        }
    }
    drop(lock);
    manager_audit_auth_status(root)
}

#[cfg_attr(not(any(target_os = "android", test)), allow(dead_code))]
pub fn manager_audit_auth_challenge(
    root: &Path,
    action: AuditAction,
    arguments_hash: &str,
) -> Result<ManagerAuditAuthChallenge> {
    validate_sha256_hex(arguments_hash, "arguments hash")?;
    let _lock = AuditLock::acquire(root, false)?;
    let key = load_key(root, false)?;
    let registry = read_manager_auth_registry(root, &key)?
        .context("Manager audit authorization key is not configured")?;
    let checkpoint = checkpoint_payload_readonly_unlocked(root, &key)?;
    manager_audit_auth_challenge_unlocked(
        root,
        action,
        arguments_hash,
        &checkpoint.inventory_hash,
        &registry,
        &key,
    )
}

fn manager_audit_auth_challenge_unlocked(
    root: &Path,
    action: AuditAction,
    arguments_hash: &str,
    inventory_hash: &str,
    registry: &ManagerAuditAuthRegistry,
    key: &[u8; 32],
) -> Result<ManagerAuditAuthChallenge> {
    clear_authorization_challenges(root)?;
    let challenge_id = hex(&random_hmac_key()?);
    let challenge = AuditAuthorizationChallenge {
        schema_version: MANAGER_AUTH_SCHEMA_VERSION,
        action,
        inventory_hash: inventory_hash.to_owned(),
        arguments_hash: arguments_hash.to_owned(),
        key_id: registry.key_id.clone(),
        challenge_id,
        created_at_unix_seconds: now(),
    };
    write_record(
        &challenge_path(root, &challenge.challenge_id),
        challenge.clone(),
        key,
    )?;
    Ok(ManagerAuditAuthChallenge {
        schema_version: challenge.schema_version,
        action: challenge.action,
        inventory_hash: challenge.inventory_hash,
        arguments_hash: challenge.arguments_hash,
        key_id: challenge.key_id,
        challenge_id: challenge.challenge_id,
        created_at_unix_seconds: challenge.created_at_unix_seconds,
    })
}

fn sealed_recovery_arguments_hash(
    seal_hash: &str,
    inventory_hash: &str,
    failure: &SealedIntegrityFailure,
) -> Result<String> {
    let bytes = serde_json::to_vec(&(
        AuditAction::RecoverSealed,
        seal_hash,
        inventory_hash,
        &failure.module_id,
        failure.corrupted_from_sequence,
        &failure.reason,
        &failure.unexpected_paths,
    ))?;
    Ok(hex(&Sha256::digest(bytes)))
}

#[cfg_attr(not(any(target_os = "android", test)), allow(dead_code))]
pub fn manager_sealed_recovery_challenge(
    root: &Path,
    module_id: &str,
) -> Result<ManagerAuditAuthChallenge> {
    validate_module_id(module_id)?;
    let _lock = AuditLock::acquire(root, false)?;
    let key = load_key(root, false)?;
    let registry = read_manager_auth_registry(root, &key)?
        .context("Manager audit authorization key is not configured")?;
    let status = sealed_integrity_status_unlocked(root, &key)?;
    let failure = status
        .failures
        .iter()
        .find(|failure| failure.module_id == module_id)
        .context("module has no Manager-sealed integrity failure")?;
    let arguments_hash =
        sealed_recovery_arguments_hash(&status.seal_hash, &status.inventory_hash, failure)?;
    manager_audit_auth_challenge_unlocked(
        root,
        AuditAction::RecoverSealed,
        &arguments_hash,
        &status.inventory_hash,
        &registry,
        &key,
    )
}

#[cfg_attr(not(any(target_os = "android", test)), allow(dead_code))]
pub fn recover_manager_sealed_module(
    root: &Path,
    module_id: &str,
    encoded_authorization: &str,
) -> Result<(
    ModuleAuditStatus,
    crate::module_audit_transaction::AuditTransactionReceipt,
)> {
    validate_module_id(module_id)?;
    let status = sealed_integrity_status(root)?;
    let failure = status
        .failures
        .iter()
        .find(|failure| failure.module_id == module_id)
        .cloned()
        .context("module has no Manager-sealed integrity failure")?;
    let arguments_hash =
        sealed_recovery_arguments_hash(&status.seal_hash, &status.inventory_hash, &failure)?;
    let targets = vec![module_id.to_owned()];
    let mut transaction = crate::module_audit_transaction::AuditTransaction::begin_at_inventory(
        root,
        encoded_authorization,
        AuditAction::RecoverSealed,
        &arguments_hash,
        &targets,
        Some(&status.inventory_hash),
    )?;

    let lock = AuditLock::acquire(root, false)?;
    let key = load_key(root, false)?;
    let recovery = SealedRecoveryRecord {
        schema_version: SCHEMA_VERSION,
        module_id: module_id.to_owned(),
        operation_id: transaction.operation_id().to_owned(),
        seal_hash: status.seal_hash,
        base_inventory_hash: status.inventory_hash,
        corrupted_from_sequence: failure.corrupted_from_sequence,
        cause: failure.cause,
        reason: failure.reason.clone(),
        unexpected_paths: failure.unexpected_paths.clone(),
    };
    let recovery_path = sealed_recovery_path(root, module_id);
    if recovery_path.exists() {
        let existing = read_sealed_recovery(root, module_id, &key)?
            .context("sealed recovery record disappeared")?;
        if existing != recovery {
            let previous_operation = read_operation(root, &existing.operation_id, &key)?
                .context("sealed recovery operation is unavailable")?;
            ensure!(
                previous_operation.state == AuditOperationState::Applied,
                "previous sealed recovery is still active; cannot start a new recovery"
            );
            write_record(&recovery_path, recovery, &key)?;
        }
    } else {
        write_record(&recovery_path, recovery, &key)?;
    }
    let events_dir = module_path(root, module_id).join("events");
    let unexpected_entries = if events_dir.is_dir() {
        audit_event_paths(&events_dir)?.1
    } else {
        Vec::new()
    };
    let current_unexpected_paths = unexpected_entries
        .iter()
        .map(|path| path.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    ensure!(
        current_unexpected_paths == failure.unexpected_paths,
        "audit event directory changed after recovery authorization"
    );
    let unexpected_quarantine = if unexpected_entries.is_empty() {
        None
    } else {
        Some(quarantine_unexpected_entries(
            root,
            module_id,
            &unexpected_entries,
        )?)
    };

    let registry = read_manager_auth_registry(root, &key)?
        .context("Manager audit authorization key is not configured")?;
    let seal = load_verified_manager_seal(root, &registry)?
        .context("Manager audit seal is not configured")?;
    let sealed_module = seal
        .payload
        .modules
        .iter()
        .find(|module| module.module_id == module_id)
        .context("failed audit module is not present in the Manager seal")?;
    let unexpected_only = failure.corrupted_from_sequence
        == u64::try_from(sealed_module.event_hashes.len())
            .unwrap_or(u64::MAX)
            .saturating_add(1);
    if unexpected_only {
        let quarantine =
            unexpected_quarantine.context("unexpected audit entries were not quarantined")?;
        let mut chain = verify_chain(root, module_id, &key, false)?;
        append_incident(
            root,
            module_id,
            &key,
            &mut chain.events,
            failure.corrupted_from_sequence,
            failure.cause,
            failure.reason,
            &quarantine,
        )?;
    }
    let module_status = if unexpected_only {
        verify_module_unlocked(root, module_id, false)?
    } else {
        verify_module_unlocked(root, module_id, true)?
    };
    drop(lock);
    transaction.complete_target(module_id)?;
    let receipt = transaction.commit()?;
    Ok((module_status, receipt))
}

#[cfg(test)]
fn begin_manager_audit_operation(
    root: &Path,
    encoded_authorization: &str,
    expected_action: AuditAction,
    expected_arguments_hash: &str,
    expected_targets: &[String],
) -> Result<AuthorizedAuditOperation> {
    begin_manager_audit_operation_at_inventory(
        root,
        encoded_authorization,
        expected_action,
        expected_arguments_hash,
        expected_targets,
        None,
    )
}

/// Canonical digest bound into Manager authorization challenges for an audit
/// mutation. Keeping this encoding in the authenticated store avoids response
/// and module-management code implementing subtly different contracts.
#[cfg_attr(not(any(target_os = "android", test)), allow(dead_code))]
pub(crate) fn manager_operation_arguments_hash(
    action: AuditAction,
    targets: &[String],
) -> Result<String> {
    let bytes = serde_json::to_vec(&(action, targets))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

pub fn incident_close_arguments_hash(
    root: &Path,
    module_id: &str,
    incident_id: &str,
) -> Result<String> {
    validate_module_id(module_id)?;
    validate_sha256_hex(incident_id, "incident id")?;
    let history = read_module_history(root, module_id, true)?;
    let incident = history
        .status
        .incidents
        .iter()
        .find(|incident| incident.incident_id == incident_id)
        .context("audit incident does not exist")?;
    ensure!(
        matches!(
            incident.state,
            AuditIncidentState::Resolved | AuditIncidentState::Closed
        ),
        "audit incident is still active and cannot be closed"
    );
    let bytes = serde_json::to_vec(&(AuditAction::CloseIncident, module_id, incident_id))?;
    Ok(hex(&Sha256::digest(bytes)))
}

pub fn close_incident_challenge(
    root: &Path,
    module_id: &str,
    incident_id: &str,
) -> Result<ManagerAuditAuthChallenge> {
    let arguments_hash = incident_close_arguments_hash(root, module_id, incident_id)?;
    manager_audit_auth_challenge(root, AuditAction::CloseIncident, &arguments_hash)
}

pub fn close_incident(
    root: &Path,
    module_id: &str,
    incident_id: &str,
    encoded_authorization: &str,
) -> Result<(
    ModuleAuditStatus,
    crate::module_audit_transaction::AuditTransactionReceipt,
)> {
    let arguments_hash = incident_close_arguments_hash(root, module_id, incident_id)?;
    let targets = vec![module_id.to_owned()];
    let mut transaction = crate::module_audit_transaction::AuditTransaction::begin(
        root,
        encoded_authorization,
        AuditAction::CloseIncident,
        &arguments_hash,
        &targets,
    )?;
    if transaction.is_committed() {
        let status = read_module_history(root, module_id, false)?.status;
        let receipt = transaction.commit()?;
        return Ok((status, receipt));
    }

    let lock = AuditLock::acquire(root, false)?;
    let key = load_key(root, false)?;
    let chain = verify_chain(root, module_id, &key, true)?;
    let incident = incident_statuses(&chain.events)
        .into_iter()
        .find(|incident| incident.incident_id == incident_id)
        .context("audit incident disappeared")?;
    ensure!(
        incident.state == AuditIncidentState::Resolved,
        "audit incident is not resolved or was already closed"
    );
    append_event(
        root,
        module_id,
        AuditEventKind::IncidentClosed {
            incident_id: incident_id.to_owned(),
            operation_id: transaction.operation_id().to_owned(),
            resolution: "secure_module_removal_verified".to_owned(),
        },
    )?;
    drop(lock);
    transaction.complete_target(module_id)?;
    let receipt = transaction.commit()?;
    let status = read_module_history(root, module_id, false)?.status;
    Ok((status, receipt))
}

pub(crate) fn begin_manager_audit_operation_at_inventory(
    root: &Path,
    encoded_authorization: &str,
    expected_action: AuditAction,
    expected_arguments_hash: &str,
    expected_targets: &[String],
    expected_inventory_hash: Option<&str>,
) -> Result<AuthorizedAuditOperation> {
    let token_bytes = decode_hex(encoded_authorization)?;
    let token: SignedAuditAuthorization =
        serde_json::from_slice(&token_bytes).context("parse Manager audit authorization")?;
    ensure!(
        token.schema_version == MANAGER_AUTH_SCHEMA_VERSION,
        "unsupported Manager audit authorization schema"
    );
    ensure!(
        token.action == expected_action,
        "audit authorization action mismatch"
    );
    ensure!(
        token.arguments_hash == expected_arguments_hash,
        "audit authorization arguments mismatch"
    );
    validate_sha256_hex(&token.inventory_hash, "inventory hash")?;
    validate_sha256_hex(&token.arguments_hash, "arguments hash")?;
    validate_sha256_hex(&token.challenge_id, "challenge id")?;
    validate_sha256_hex(&token.key_id, "Manager key id")?;
    ensure!(
        expected_targets.windows(2).all(|pair| pair[0] < pair[1]),
        "audit operation targets are not canonical"
    );
    let operation_id = hex(&Sha256::digest(&token_bytes));
    let _lock = AuditLock::acquire(root, false)?;
    let hmac_key = load_key(root, false)?;
    let registry = read_manager_auth_registry(root, &hmac_key)?
        .context("Manager audit authorization key is not configured")?;
    ensure!(
        token.key_id == registry.key_id,
        "Manager authorization key mismatch"
    );

    if let Some(operation) = read_operation(root, &operation_id, &hmac_key)? {
        ensure_operation_matches(
            &operation,
            &operation_id,
            expected_action,
            expected_arguments_hash,
            expected_targets,
        )?;
        ensure!(
            operation.state != AuditOperationState::Interrupted,
            "audit operation was interrupted: {}",
            operation.error.as_deref().unwrap_or("unknown failure")
        );
        recover_operation_progress(root, &hmac_key)?;
        let recovered = read_operation(root, &operation_id, &hmac_key)?
            .context("replayed audit operation disappeared during recovery")?;
        remove_challenge_if_present(root, &token.challenge_id)?;
        return Ok(authorized_operation(&recovered, true));
    }

    let challenge: AuthenticatedRecord<AuditAuthorizationChallenge> =
        read_json(&challenge_path(root, &token.challenge_id))
            .context("audit authorization challenge is unavailable or already consumed")?;
    verify_record(&challenge.record, &challenge.hmac_sha256, &hmac_key)?;
    let challenge_age = now()
        .checked_sub(challenge.record.created_at_unix_seconds)
        .context("audit authorization challenge is from the future")?;
    ensure!(
        challenge_age <= AUTH_CHALLENGE_TTL_SECONDS,
        "audit authorization challenge expired"
    );
    ensure!(
        challenge.record.schema_version == MANAGER_AUTH_SCHEMA_VERSION
            && challenge.record.action == token.action
            && challenge.record.inventory_hash == token.inventory_hash
            && challenge.record.arguments_hash == token.arguments_hash
            && challenge.record.key_id == token.key_id
            && challenge.record.challenge_id == token.challenge_id
            && challenge.record.created_at_unix_seconds == token.created_at_unix_seconds,
        "audit authorization does not match its ksud challenge"
    );
    let inventory_hash = match expected_inventory_hash {
        Some(expected) => expected.to_owned(),
        None => checkpoint_payload_unlocked(root)?.inventory_hash,
    };
    ensure!(
        token.inventory_hash == inventory_hash,
        "audit inventory changed after authorization"
    );
    let public_key = decode_hex(&registry.public_key_hex)?;
    let verifying_key =
        VerifyingKey::from_sec1_bytes(&public_key).context("invalid registered Manager key")?;
    let signature = Signature::from_der(&decode_hex(&token.signature_der_hex)?)
        .context("invalid Manager audit authorization signature")?;
    let message = audit_authorization_message(
        token.action,
        &token.inventory_hash,
        &token.arguments_hash,
        &token.key_id,
        &token.challenge_id,
        token.created_at_unix_seconds,
    );
    verifying_key
        .verify(message.as_bytes(), &signature)
        .context("Manager audit authorization signature rejected")?;

    if let Some(operation) = find_resumable_operation(
        root,
        &hmac_key,
        expected_action,
        expected_arguments_hash,
        expected_targets,
    )? {
        let resumable_id = operation.operation_id;
        recover_operation_progress(root, &hmac_key)?;
        let recovered = read_operation(root, &resumable_id, &hmac_key)?
            .context("resumable audit operation disappeared during recovery")?;
        ensure!(
            recovered.state != AuditOperationState::Interrupted,
            "audit operation was interrupted: {}",
            recovered.error.as_deref().unwrap_or("unknown failure")
        );
        remove_challenge_if_present(root, &token.challenge_id)?;
        return Ok(authorized_operation(&recovered, true));
    }
    recover_operation_progress(root, &hmac_key)?;
    verify_authorized_inventory_unchanged(
        root,
        &hmac_key,
        expected_action,
        expected_arguments_hash,
        expected_targets,
        &inventory_hash,
        expected_inventory_hash,
    )?;
    ensure!(
        !read_operation_records(root, &hmac_key)?
            .iter()
            .any(|operation| operation.state == AuditOperationState::Applying),
        "another audit mutation is still active"
    );

    let operation = AuditOperationRecord {
        schema_version: SCHEMA_VERSION,
        operation_id,
        action: expected_action,
        base_inventory_hash: token.inventory_hash,
        arguments_hash: expected_arguments_hash.to_owned(),
        authorization_hex: encoded_authorization.to_owned(),
        targets: expected_targets.to_vec(),
        completed_targets: Vec::new(),
        state: AuditOperationState::Applying,
        error: None,
        started_at_unix_seconds: now(),
        updated_at_unix_seconds: now(),
    };
    validate_operation_record(&operation)?;
    write_record(
        &operation_path(root, &operation.operation_id),
        operation.clone(),
        &hmac_key,
    )?;
    pending_hmac_key(root, &hmac_key, true)?;
    remove_challenge_if_present(root, &token.challenge_id)?;
    Ok(authorized_operation(&operation, false))
}

fn verify_authorized_inventory_unchanged(
    root: &Path,
    key: &[u8; 32],
    action: AuditAction,
    expected_arguments_hash: &str,
    expected_targets: &[String],
    authorized_inventory_hash: &str,
    expected_inventory_hash: Option<&str>,
) -> Result<()> {
    match action.descriptor().authorization_inventory {
        AuditAuthorizationInventory::CurrentCheckpoint => {
            ensure!(
                expected_inventory_hash.is_none(),
                "current-checkpoint audit action supplied a sealed inventory override"
            );
            ensure!(
                checkpoint_payload_unlocked(root)?.inventory_hash == authorized_inventory_hash,
                "audit inventory changed while recovering previous transactions"
            );
        }
        AuditAuthorizationInventory::ManagerSealedDamage => {
            let expected_inventory_hash = expected_inventory_hash
                .context("Manager-sealed recovery inventory is unavailable")?;
            ensure!(
                expected_inventory_hash == authorized_inventory_hash,
                "Manager-sealed recovery authorization inventory mismatch"
            );
            ensure!(
                expected_targets.len() == 1,
                "Manager-sealed recovery requires exactly one module target"
            );
            let status = sealed_integrity_status_unlocked(root, key)?;
            ensure!(
                status.inventory_hash == authorized_inventory_hash,
                "Manager-sealed recovery inventory changed after authorization"
            );
            let failure = status
                .failures
                .iter()
                .find(|failure| failure.module_id.as_str() == expected_targets[0].as_str())
                .context("Manager-sealed recovery target no longer has integrity damage")?;
            ensure!(
                sealed_recovery_arguments_hash(&status.seal_hash, &status.inventory_hash, failure,)?
                    == expected_arguments_hash,
                "Manager-sealed integrity damage changed after authorization"
            );
        }
    }
    Ok(())
}

fn ensure_operation_matches(
    operation: &AuditOperationRecord,
    operation_id: &str,
    action: AuditAction,
    arguments_hash: &str,
    targets: &[String],
) -> Result<()> {
    ensure!(
        operation.operation_id == operation_id
            && hex(&Sha256::digest(decode_hex(&operation.authorization_hex)?)) == operation_id
            && operation.action == action
            && operation.arguments_hash == arguments_hash
            && operation.targets == targets,
        "replayed authorization does not match its original audit operation"
    );
    Ok(())
}

fn authorized_operation(
    operation: &AuditOperationRecord,
    replayed: bool,
) -> AuthorizedAuditOperation {
    AuthorizedAuditOperation {
        operation_id: operation.operation_id.clone(),
        targets: operation.targets.clone(),
        completed_targets: operation.completed_targets.clone(),
        base_inventory_hash: operation.base_inventory_hash.clone(),
        applied: operation.state == AuditOperationState::Applied,
        replayed,
    }
}

fn find_resumable_operation(
    root: &Path,
    key: &[u8; 32],
    action: AuditAction,
    arguments_hash: &str,
    targets: &[String],
) -> Result<Option<AuditOperationRecord>> {
    let directory = root.join(OPERATIONS_DIR);
    if !directory.exists() {
        return Ok(None);
    }
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let authenticated: AuthenticatedRecord<AuditOperationRecord> = read_json(&entry.path())?;
        verify_record(&authenticated.record, &authenticated.hmac_sha256, key)?;
        validate_operation_record(&authenticated.record)?;
        if authenticated.record.state == AuditOperationState::Applying
            && authenticated.record.action == action
            && authenticated.record.arguments_hash == arguments_hash
            && authenticated.record.targets == targets
        {
            return Ok(Some(authenticated.record));
        }
    }
    Ok(None)
}

fn read_operation(
    root: &Path,
    operation_id: &str,
    key: &[u8; 32],
) -> Result<Option<AuditOperationRecord>> {
    let path = operation_path(root, operation_id);
    if !path.exists() {
        return Ok(None);
    }
    let authenticated: AuthenticatedRecord<AuditOperationRecord> = read_json(&path)?;
    verify_record(&authenticated.record, &authenticated.hmac_sha256, key)?;
    validate_operation_record(&authenticated.record)?;
    Ok(Some(authenticated.record))
}

fn remove_challenge_if_present(root: &Path, challenge_id: &str) -> Result<()> {
    let path = challenge_path(root, challenge_id);
    if path.exists() {
        std::fs::remove_file(&path).context("consume audit authorization challenge")?;
        sync_dir(path.parent().context("challenge has no parent")?)?;
    }
    Ok(())
}

fn clear_authorization_challenges(root: &Path) -> Result<()> {
    let directory = root.join(CHALLENGES_DIR);
    if !directory.exists() {
        return Ok(());
    }
    for entry in std::fs::read_dir(&directory).context("read audit authorization challenges")? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            std::fs::remove_file(entry.path()).context("invalidate old audit challenge")?;
        }
    }
    sync_dir(&directory)
}

fn read_manager_auth_registry(
    root: &Path,
    key: &[u8; 32],
) -> Result<Option<ManagerAuditAuthRegistry>> {
    let path = manager_auth_path(root);
    if !path.exists() {
        return Ok(None);
    }
    let authenticated: AuthenticatedRecord<ManagerAuditAuthRegistry> = read_json(&path)?;
    verify_record(&authenticated.record, &authenticated.hmac_sha256, key)?;
    ensure!(
        authenticated.record.schema_version == MANAGER_AUTH_SCHEMA_VERSION,
        "unsupported Manager audit authorization registry schema"
    );
    let public_key = decode_hex(&authenticated.record.public_key_hex)?;
    ensure!(
        authenticated.record.key_id == hex(&Sha256::digest(&public_key)),
        "Manager audit authorization key id mismatch"
    );
    VerifyingKey::from_sec1_bytes(&public_key).context("invalid registered Manager key")?;
    Ok(Some(authenticated.record))
}

fn read_manager_auth_registry_during_rotation(
    root: &Path,
    previous: &[u8; 32],
    next: &[u8; 32],
) -> Result<Option<ManagerAuditAuthRegistry>> {
    let path = manager_auth_path(root);
    if !path.exists() {
        return Ok(None);
    }
    let authenticated: AuthenticatedRecord<ManagerAuditAuthRegistry> = read_json(&path)?;
    if verify_record(&authenticated.record, &authenticated.hmac_sha256, previous).is_err() {
        verify_record(&authenticated.record, &authenticated.hmac_sha256, next)?;
    }
    ensure!(
        authenticated.record.schema_version == MANAGER_AUTH_SCHEMA_VERSION,
        "unsupported Manager audit authorization registry schema"
    );
    let public_key = decode_hex(&authenticated.record.public_key_hex)?;
    ensure!(
        authenticated.record.key_id == hex(&Sha256::digest(&public_key)),
        "Manager audit authorization key id mismatch"
    );
    VerifyingKey::from_sec1_bytes(&public_key).context("invalid registered Manager key")?;
    Ok(Some(authenticated.record))
}

#[cfg_attr(not(any(target_os = "android", test)), allow(dead_code))]
fn audit_authorization_message(
    action: AuditAction,
    inventory_hash: &str,
    arguments_hash: &str,
    key_id: &str,
    challenge_id: &str,
    created_at_unix_seconds: u64,
) -> String {
    format!(
        "kernelsu-audit-authorization-v2\n{action}\n{inventory_hash}\n{arguments_hash}\n{key_id}\n{challenge_id}\n{created_at_unix_seconds}\n"
    )
}

fn validate_sha256_hex(value: &str, name: &str) -> Result<()> {
    ensure!(
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid audit authorization {name}"
    );
    Ok(())
}

fn decode_hex(value: &str) -> Result<Vec<u8>> {
    ensure!(value.len().is_multiple_of(2), "invalid hexadecimal input");
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char)
                .to_digit(16)
                .context("invalid hexadecimal input")?;
            let low = (pair[1] as char)
                .to_digit(16)
                .context("invalid hexadecimal input")?;
            Ok(((high << 4) | low) as u8)
        })
        .collect()
}

fn decode_base64(value: &str) -> Result<Vec<u8>> {
    ensure!(value.len().is_multiple_of(4), "invalid base64 length");
    let mut output = Vec::with_capacity(value.len() / 4 * 3);
    let chunks = value.as_bytes().chunks_exact(4);
    let chunk_count = chunks.len();
    for (index, chunk) in chunks.enumerate() {
        let last = index + 1 == chunk_count;
        let padding = match (chunk[2], chunk[3]) {
            (b'=', b'=') => 2,
            (_, b'=') => 1,
            (b'=', _) => bail!("invalid base64 padding"),
            _ => 0,
        };
        ensure!(last || padding == 0, "invalid base64 padding");
        let a = base64_value(chunk[0])?;
        let b = base64_value(chunk[1])?;
        let c = if padding == 2 {
            0
        } else {
            base64_value(chunk[2])?
        };
        let d = if padding >= 1 {
            0
        } else {
            base64_value(chunk[3])?
        };
        output.push((a << 2) | (b >> 4));
        if padding < 2 {
            output.push((b << 4) | (c >> 2));
        }
        if padding == 0 {
            output.push((c << 6) | d);
        }
    }
    Ok(output)
}

fn base64_value(value: u8) -> Result<u8> {
    match value {
        b'A'..=b'Z' => Ok(value - b'A'),
        b'a'..=b'z' => Ok(value - b'a' + 26),
        b'0'..=b'9' => Ok(value - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => bail!("invalid base64 character"),
    }
}

#[cfg(test)]
fn encode_base64(value: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(value.len().div_ceil(3) * 4);
    for chunk in value.chunks(3) {
        let a = chunk[0];
        let b = chunk.get(1).copied().unwrap_or(0);
        let c = chunk.get(2).copied().unwrap_or(0);
        output.push(char::from(ALPHABET[usize::from(a >> 2)]));
        output.push(char::from(
            ALPHABET[usize::from(((a & 0x03) << 4) | (b >> 4))],
        ));
        output.push(if chunk.len() > 1 {
            char::from(ALPHABET[usize::from(((b & 0x0f) << 2) | (c >> 6))])
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            char::from(ALPHABET[usize::from(c & 0x3f)])
        } else {
            '='
        });
    }
    output
}

fn manager_auth_path(root: &Path) -> PathBuf {
    root.join(MANAGER_AUTH_FILE)
}

fn manager_seal_path(root: &Path) -> PathBuf {
    root.join(MANAGER_SEAL_FILE)
}

fn challenge_path(root: &Path, challenge_id: &str) -> PathBuf {
    root.join(CHALLENGES_DIR)
        .join(format!("{challenge_id}.json"))
}

fn operation_path(root: &Path, operation_id: &str) -> PathBuf {
    root.join(OPERATIONS_DIR)
        .join(format!("{operation_id}.json"))
}

fn operation_trash_path(root: &Path, operation_id: &str, module_id: &str) -> PathBuf {
    root.join(OPERATION_TRASH_DIR)
        .join(operation_id)
        .join(module_dir_name(module_id))
}

fn operation_tombstone_path(root: &Path, module_id: &str, operation_id: &str) -> PathBuf {
    root.join("tombstones")
        .join(module_dir_name(module_id))
        .join(format!("operation-{operation_id}.json"))
}

#[cfg_attr(not(any(target_os = "android", test)), allow(dead_code))]
fn append_event(root: &Path, module_id: &str, kind: AuditEventKind) -> Result<()> {
    let key = load_key(root, true)?;
    verify_module_unlocked(root, module_id, true)?;
    let chain = verify_chain(root, module_id, &key, true)?;
    let sequence = u64::try_from(chain.events.len())
        .context("too many audit events")?
        .saturating_add(1);
    let previous_hash = chain
        .events
        .last()
        .map_or_else(|| GENESIS_HASH.to_owned(), |entry| entry.event_hash.clone());
    let event = AuditEvent {
        schema_version: EVENT_SCHEMA_VERSION,
        module_id: module_id.to_owned(),
        sequence,
        timestamp_unix_seconds: now(),
        previous_hash,
        kind,
    };
    write_event(root, module_id, &key, event)?;
    pending_hmac_key(root, &key, true)?;
    Ok(())
}

pub fn append_global_event(root: &Path, module_id: &str, kind: AuditEventKind) -> Result<()> {
    validate_module_id(module_id)?;
    let _lock = AuditLock::acquire(root, true)?;
    append_event(root, module_id, kind)
}

fn verify_chain(
    root: &Path,
    module_id: &str,
    key: &[u8; 32],
    repair: bool,
) -> Result<VerifiedChain> {
    let sealed_event_hashes = verified_sealed_event_hashes(root, module_id, key)?;
    let events_dir = module_path(root, module_id).join("events");
    if !events_dir.exists() {
        ensure!(
            sealed_event_hashes.is_empty(),
            "Manager-sealed audit history is missing"
        );
        return Ok(VerifiedChain {
            events: Vec::new(),
            state: VerificationState::Empty,
        });
    }
    let (mut paths, unexpected) = audit_event_paths(&events_dir)?;
    paths.sort();
    ensure!(
        paths.len() >= sealed_event_hashes.len(),
        "Manager-sealed audit history was truncated"
    );
    if !unexpected.is_empty() && !sealed_event_hashes.is_empty() {
        bail!(
            "Manager-sealed audit event directory contains unexpected entry {}",
            unexpected[0].display()
        );
    }

    let mut valid = Vec::new();
    let mut failure = None;
    for (index, path) in paths.iter().enumerate() {
        let expected_sequence = u64::try_from(index).unwrap_or(u64::MAX).saturating_add(1);
        let sealed_hash = sealed_event_hashes.get(index).map(String::as_str);
        let result =
            verify_event_file(path, module_id, expected_sequence, &valid, key, sealed_hash);
        match result {
            Ok(event) => valid.push(event),
            Err(error) if sealed_hash.is_some() => {
                return Err(error).context("Manager-sealed audit event integrity failure");
            }
            Err(error) => {
                failure = Some((index, expected_sequence, format!("{error:#}")));
                break;
            }
        }
    }

    let Some((corrupted_from_sequence, reason, corrupt_paths)) = failure
        .map(|(index, sequence, reason)| (sequence, reason, paths[index..].to_vec()))
        .or_else(|| {
            (!unexpected.is_empty()).then(|| {
                (
                    u64::try_from(paths.len())
                        .unwrap_or(u64::MAX)
                        .saturating_add(1),
                    format!(
                        "audit event directory contains unexpected entry {}",
                        unexpected[0].display()
                    ),
                    unexpected,
                )
            })
        })
    else {
        let state = if valid.is_empty() {
            VerificationState::Empty
        } else {
            VerificationState::Verified
        };
        return Ok(VerifiedChain {
            events: valid,
            state,
        });
    };
    ensure!(repair, "audit history integrity failure: {reason}");

    let quarantine = quarantine_suffix(root, module_id, &corrupt_paths)?;
    append_incident(
        root,
        module_id,
        key,
        &mut valid,
        corrupted_from_sequence,
        if corrupted_from_sequence > u64::try_from(paths.len()).unwrap_or(u64::MAX) {
            AuditIncidentCause::UnexpectedAuditPath
        } else {
            AuditIncidentCause::AuditEventInvalid
        },
        reason,
        &quarantine,
    )?;
    Ok(VerifiedChain {
        events: valid,
        state: VerificationState::Recovered,
    })
}

fn append_incident(
    root: &Path,
    module_id: &str,
    key: &[u8; 32],
    events: &mut Vec<AuthenticatedEvent>,
    corrupted_from_sequence: u64,
    cause: AuditIncidentCause,
    reason: String,
    quarantine: &Path,
) -> Result<()> {
    let previous_hash = events
        .last()
        .map_or_else(|| GENESIS_HASH.to_owned(), |entry| entry.event_hash.clone());
    let sequence = u64::try_from(events.len())
        .context("too many audit events")?
        .saturating_add(1);
    let incident = AuditEvent {
        schema_version: EVENT_SCHEMA_VERSION,
        module_id: module_id.to_owned(),
        sequence,
        timestamp_unix_seconds: now(),
        previous_hash,
        kind: AuditEventKind::IntegrityIncident {
            corrupted_from_sequence,
            cause,
            reason,
            quarantine: quarantine.to_string_lossy().into_owned(),
        },
    };
    write_event(root, module_id, key, incident)?;
    let path = event_path(root, module_id, sequence);
    events.push(verify_event_file(
        &path, module_id, sequence, events, key, None,
    )?);
    Ok(())
}

fn verify_event_file(
    path: &Path,
    module_id: &str,
    expected_sequence: u64,
    preceding: &[AuthenticatedEvent],
    key: &[u8; 32],
    sealed_hash: Option<&str>,
) -> Result<AuthenticatedEvent> {
    let raw = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let entry: AuthenticatedEvent =
        serde_json::from_slice(&raw).with_context(|| format!("parse {}", path.display()))?;
    let mut canonical = serde_json::to_vec_pretty(&entry)?;
    canonical.push(b'\n');
    ensure!(raw == canonical, "audit event encoding is not canonical");
    ensure!(
        entry.event.schema_version == EVENT_SCHEMA_VERSION,
        "unsupported event schema"
    );
    ensure!(
        entry.event.module_id == module_id,
        "event module id mismatch"
    );
    ensure!(
        entry.event.sequence == expected_sequence,
        "event sequence mismatch"
    );
    let expected_previous = preceding
        .last()
        .map_or(GENESIS_HASH, |previous| previous.event_hash.as_str());
    ensure!(
        entry.event.previous_hash == expected_previous,
        "event chain mismatch"
    );
    let bytes = serde_json::to_vec(&entry.event)?;
    ensure!(
        entry.hmac_sha256.len() == 64
            && entry
                .hmac_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "invalid event authentication tag"
    );
    ensure!(
        constant_time_eq(
            entry.event_hash.as_bytes(),
            authenticated_event_hash(&bytes, &entry.hmac_sha256).as_bytes()
        ),
        "event hash mismatch"
    );
    if let Some(sealed_hash) = sealed_hash {
        ensure!(
            constant_time_eq(entry.event_hash.as_bytes(), sealed_hash.as_bytes()),
            "event does not match its Manager seal"
        );
    } else {
        ensure!(
            constant_time_eq(
                entry.hmac_sha256.as_bytes(),
                hex(&hmac_sha256(key, &bytes)).as_bytes()
            ),
            "event authentication mismatch"
        );
    }
    Ok(entry)
}

fn write_event(root: &Path, module_id: &str, key: &[u8; 32], event: AuditEvent) -> Result<()> {
    let bytes = serde_json::to_vec(&event)?;
    let hmac_sha256 = hex(&hmac_sha256(key, &bytes));
    let entry = AuthenticatedEvent {
        event_hash: authenticated_event_hash(&bytes, &hmac_sha256),
        hmac_sha256,
        event,
    };
    let path = event_path(root, module_id, entry.event.sequence);
    ensure_dir(path.parent().context("event path has no parent")?)?;
    atomic_write_json(&path, &entry)
}

fn authenticated_event_hash(event: &[u8], hmac_sha256: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"kernelsu-module-audit-event-v2\0");
    digest.update(u64::try_from(event.len()).unwrap_or(u64::MAX).to_le_bytes());
    digest.update(event);
    digest.update(hmac_sha256.as_bytes());
    hex(&digest.finalize())
}

fn audit_event_paths(events_dir: &Path) -> Result<(Vec<PathBuf>, Vec<PathBuf>)> {
    let mut events = Vec::new();
    let mut unexpected = Vec::new();
    for entry in std::fs::read_dir(events_dir).context("read audit events")? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let expected_name = name.len() == 25
            && name.ends_with(".json")
            && name[..20].bytes().all(|byte| byte.is_ascii_digit());
        if entry.file_type()?.is_file() && expected_name {
            events.push(path);
        } else {
            unexpected.push(path);
        }
    }
    unexpected.sort();
    Ok((events, unexpected))
}

fn write_record<T: Serialize>(path: &Path, record: T, key: &[u8; 32]) -> Result<()> {
    let bytes = serde_json::to_vec(&record)?;
    let envelope = AuthenticatedRecord {
        record,
        hmac_sha256: hex(&hmac_sha256(key, &bytes)),
    };
    atomic_write_json(path, &envelope)
}

fn verify_record<T: Serialize>(record: &T, tag: &str, key: &[u8; 32]) -> Result<()> {
    let bytes = serde_json::to_vec(record)?;
    ensure!(
        constant_time_eq(tag.as_bytes(), hex(&hmac_sha256(key, &bytes)).as_bytes()),
        "record authentication mismatch"
    );
    Ok(())
}

fn quarantine_suffix(root: &Path, module_id: &str, paths: &[PathBuf]) -> Result<PathBuf> {
    let directory = module_path(root, module_id)
        .join("quarantine")
        .join(format!("{}-{}", now(), std::process::id()));
    ensure_dir(&directory)?;
    for path in paths {
        let name = path.file_name().context("audit event has no filename")?;
        std::fs::rename(path, directory.join(name)).context("quarantine corrupt audit event")?;
    }
    sync_dir(directory.parent().context("quarantine has no parent")?)?;
    Ok(directory)
}

fn quarantine_unexpected_entries(
    root: &Path,
    module_id: &str,
    paths: &[PathBuf],
) -> Result<PathBuf> {
    let directory = module_path(root, module_id)
        .join("quarantine")
        .join(format!("{}-{}", now(), std::process::id()));
    ensure_dir(&directory)?;
    for path in paths {
        let name = path.file_name().context("audit event has no filename")?;
        std::fs::rename(path, directory.join(name)).context("quarantine unexpected audit event")?;
    }
    sync_dir(directory.parent().context("quarantine has no parent")?)?;
    Ok(directory)
}

fn load_key(root: &Path, create: bool) -> Result<[u8; 32]> {
    let path = root.join(KEY_FILE);
    if path.exists() {
        return recover_pending_hmac_rotation(root, read_key(root)?);
    }
    ensure!(create, "module audit authentication key is unavailable");
    ensure!(
        !root.join("modules").exists(),
        "module audit key is missing while history exists"
    );
    ensure_dir(root)?;
    let mut key = [0_u8; 32];
    File::open("/dev/urandom")
        .context("open system random source")?
        .read_exact(&mut key)
        .context("generate module audit authentication key")?;
    atomic_write(&path, &key)?;
    Ok(key)
}

fn read_key(root: &Path) -> Result<[u8; 32]> {
    let path = root.join(KEY_FILE);
    let mut key = [0_u8; 32];
    let mut file = File::open(&path).context("open module audit authentication key")?;
    file.read_exact(&mut key)
        .context("read module audit authentication key")?;
    let mut extra = [0_u8; 1];
    ensure!(
        file.read(&mut extra)? == 0,
        "invalid module audit authentication key length"
    );
    Ok(key)
}

fn hmac_key_id(key: &[u8; 32]) -> String {
    hex(&Sha256::digest(key))
}

fn pending_hmac_key(root: &Path, key: &[u8; 32], create: bool) -> Result<PendingHmacKey> {
    let path = root.join(NEXT_KEY_FILE);
    if path.exists() {
        let pending: AuthenticatedRecord<PendingHmacKey> = read_json(&path)?;
        verify_record(&pending.record, &pending.hmac_sha256, key)?;
        validate_pending_hmac_key(&pending.record, key)?;
        return Ok(pending.record);
    }
    ensure!(create, "pending module audit HMAC key is unavailable");
    let next_key = random_hmac_key()?;
    let pending = PendingHmacKey {
        schema_version: SCHEMA_VERSION,
        current_key_id: hmac_key_id(key),
        next_key_hex: hex(&next_key),
    };
    write_record(&path, pending.clone(), key)?;
    Ok(pending)
}

fn validate_pending_hmac_key(pending: &PendingHmacKey, current: &[u8; 32]) -> Result<()> {
    ensure!(
        pending.schema_version == SCHEMA_VERSION,
        "unsupported pending HMAC key schema"
    );
    ensure!(
        pending.current_key_id == hmac_key_id(current),
        "pending HMAC key does not match the current key"
    );
    let next = pending.next_key()?;
    ensure!(next != *current, "pending HMAC key did not rotate");
    Ok(())
}

fn random_hmac_key() -> Result<[u8; 32]> {
    let mut key = [0_u8; 32];
    File::open("/dev/urandom")
        .context("open system random source")?
        .read_exact(&mut key)
        .context("generate module audit authentication key")?;
    Ok(key)
}

fn recover_pending_hmac_rotation(root: &Path, current: [u8; 32]) -> Result<[u8; 32]> {
    let path = root.join(NEXT_KEY_FILE);
    if !path.exists() {
        return Ok(current);
    }
    let pending: AuthenticatedRecord<PendingHmacKey> = read_json(&path)?;
    let current_id = hmac_key_id(&current);
    if pending.record.current_key_id == current_id {
        verify_record(&pending.record, &pending.hmac_sha256, &current)?;
        validate_pending_hmac_key(&pending.record, &current)?;
        let next = pending.record.next_key()?;
        let registry = read_manager_auth_registry_during_rotation(root, &current, &next)
            .ok()
            .flatten();
        let seal = match registry {
            Some(registry) => load_verified_manager_seal(root, &registry)?,
            None => None,
        };
        if let Some(seal) = seal
            && seal.payload.hmac_key_id == current_id
            && seal.payload.next_hmac_key_id == pending.record.next_key_id()?
        {
            complete_hmac_rotation(root, &current, &seal.payload, &seal.seal_hash)?;
            return pending_hmac_key_after_rotation(root, &pending.record);
        }
        return Ok(current);
    }
    if pending.record.next_key_id()? == current_id {
        std::fs::remove_file(&path).context("finish module audit HMAC key rotation")?;
        sync_dir(root)?;
        return Ok(current);
    }
    bail!("module audit HMAC key rotation state is inconsistent")
}

fn pending_hmac_key_after_rotation(root: &Path, pending: &PendingHmacKey) -> Result<[u8; 32]> {
    ensure!(
        !root.join(NEXT_KEY_FILE).exists(),
        "module audit HMAC key rotation did not finish"
    );
    pending.next_key()
}

fn complete_hmac_rotation(
    root: &Path,
    current: &[u8; 32],
    sealed: &CheckpointPayload,
    seal_hash: &str,
) -> Result<()> {
    if sealed.next_hmac_key_id == sealed.hmac_key_id {
        return Ok(());
    }
    let pending = pending_hmac_key(root, current, false)?;
    ensure!(
        sealed.hmac_key_id == hmac_key_id(current),
        "seal HMAC key mismatch"
    );
    ensure!(
        sealed.next_hmac_key_id == pending.next_key_id()?,
        "seal did not authorize the pending HMAC key"
    );
    let next = pending.next_key()?;
    let registry = read_manager_auth_registry_during_rotation(root, current, &next)?
        .context("Manager audit authorization key is not configured")?;
    let stored_seal = load_verified_manager_seal(root, &registry)?
        .context("Manager audit seal is unavailable during HMAC rotation")?;
    ensure!(
        stored_seal.seal_hash == seal_hash,
        "HMAC rotation seal mismatch"
    );
    reauthenticate_audit_metadata(root, current, &next)?;
    atomic_write(&root.join(KEY_FILE), &next)?;
    std::fs::remove_file(root.join(NEXT_KEY_FILE))
        .context("remove completed HMAC rotation marker")?;
    sync_dir(root)
}

fn reauthenticate_audit_metadata(root: &Path, previous: &[u8; 32], next: &[u8; 32]) -> Result<()> {
    rewrite_authenticated_file::<ManagerAuditAuthRegistry>(
        &manager_auth_path(root),
        previous,
        next,
    )?;
    rewrite_authenticated_directory::<PrunedHistoryTombstone>(
        &root.join("tombstones"),
        previous,
        next,
    )?;
    rewrite_authenticated_directory::<AuditOperationRecord>(
        &root.join(OPERATIONS_DIR),
        previous,
        next,
    )?;
    rewrite_authenticated_directory::<AuditAuthorizationChallenge>(
        &root.join(CHALLENGES_DIR),
        previous,
        next,
    )?;
    rewrite_containment_records(root, previous, next)
}

fn rewrite_containment_records(root: &Path, previous: &[u8; 32], next: &[u8; 32]) -> Result<()> {
    let directory = root.join(CONTAINMENT_DIR);
    if !directory.exists() {
        return Ok(());
    }
    for entry in std::fs::read_dir(directory)? {
        let directory = entry?.path();
        let persistent = directory.join("persistent.json");
        if persistent.is_file() {
            rewrite_authenticated_file::<PersistentQuarantineRecord>(&persistent, previous, next)?;
        }
        let persistent_result = directory.join("persistent-result.json");
        if persistent_result.is_file() {
            rewrite_authenticated_file::<PersistentContainmentResultRecord>(
                &persistent_result,
                previous,
                next,
            )?;
        }
        let state = directory.join("state.json");
        if state.is_file() {
            rewrite_authenticated_file::<ModuleContainmentRecord>(&state, previous, next)?;
        }
    }
    Ok(())
}

fn rewrite_authenticated_directory<T>(
    directory: &Path,
    previous: &[u8; 32],
    next: &[u8; 32],
) -> Result<()>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    if !directory.exists() {
        return Ok(());
    }
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            rewrite_authenticated_directory::<T>(&entry.path(), previous, next)?;
        } else {
            rewrite_authenticated_file::<T>(&entry.path(), previous, next)?;
        }
    }
    Ok(())
}

fn rewrite_authenticated_file<T>(path: &Path, previous: &[u8; 32], next: &[u8; 32]) -> Result<()>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let authenticated: AuthenticatedRecord<T> = read_json(path)?;
    if verify_record(&authenticated.record, &authenticated.hmac_sha256, previous).is_err() {
        verify_record(&authenticated.record, &authenticated.hmac_sha256, next)?;
    }
    write_record(path, authenticated.record, next)
}

fn atomic_write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    atomic_write(path, &bytes)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("output path has no parent")?;
    ensure_dir(parent)?;
    let temporary = parent.join(format!(".tmp-{}-{}", std::process::id(), now()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .context("create temporary audit file")?;
    file.write_all(bytes)
        .context("write temporary audit file")?;
    file.sync_all().context("sync temporary audit file")?;
    std::fs::rename(&temporary, path).context("commit audit file")?;
    sync_dir(parent)
}

fn ensure_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path).with_context(|| format!("create {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn sync_dir(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    serde_json::from_reader(file).with_context(|| format!("parse {}", path.display()))
}

fn module_path(root: &Path, module_id: &str) -> PathBuf {
    root.join("modules").join(module_dir_name(module_id))
}

fn module_dir_name(module_id: &str) -> String {
    module_id.to_owned()
}

fn validate_module_id(module_id: &str) -> Result<()> {
    let mut characters = module_id.chars();
    ensure!(
        module_id.len() >= 2
            && characters
                .next()
                .is_some_and(|character| character.is_ascii_alphabetic())
            && characters.all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
            }),
        "invalid module id in audit store"
    );
    Ok(())
}

fn event_path(root: &Path, module_id: &str, sequence: u64) -> PathBuf {
    module_path(root, module_id)
        .join("events")
        .join(format!("{sequence:020}.json"))
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn make_attempt_id(module_id: &str, package_sha256: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let counter = ATTEMPT_COUNTER.fetch_add(1, Ordering::Relaxed);
    let value = format!(
        "{module_id}\0{package_sha256}\0{nanos}\0{}\0{counter}",
        std::process::id()
    );
    hex(&Sha256::digest(value.as_bytes()))
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK_SIZE: usize = 64;
    let mut block = [0_u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36_u8; BLOCK_SIZE];
    let mut outer_pad = [0x5c_u8; BLOCK_SIZE];
    for index in 0..BLOCK_SIZE {
        inner_pad[index] ^= block[index];
        outer_pad[index] ^= block[index];
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner_hash = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_hash);
    outer.finalize().into()
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use ksu_module_audit::{Finding, Severity};
    use p256::ecdsa::{SigningKey, signature::Signer};
    use tempfile::TempDir;

    fn report(module_id: &str, package_hash: &str) -> AuditReport {
        AuditReport {
            schema_version: 1,
            package_sha256: package_hash.repeat(64 / package_hash.len()),
            module_id: Some(module_id.to_owned()),
            findings: vec![Finding {
                rule_id: "KSU-AUDIT-TEST-001".to_owned(),
                severity: Severity::Notice,
                path: "customize.sh".to_owned(),
                line: Some(1),
                title: "test finding".to_owned(),
                evidence: "curl example.invalid".to_owned(),
                provenance: Vec::new(),
            }],
            scanned_files: 2,
            derived_artifacts: 0,
        }
    }

    fn record(root: &Path, module_id: &str, package_hash: &str) {
        let receipt = begin_install(root, report(module_id, package_hash)).unwrap();
        finish_install(root, receipt, InstallOutcome::Installed, None).unwrap();
    }

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes((&[seed; 32]).into()).unwrap()
    }

    fn public_key_hex(signing_key: &SigningKey) -> String {
        hex(signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes())
    }

    fn authorization_token(
        root: &Path,
        signing_key: &SigningKey,
        action: AuditAction,
        arguments_hash: &str,
    ) -> String {
        let challenge = manager_audit_auth_challenge(root, action, arguments_hash).unwrap();
        let message = audit_authorization_message(
            action,
            &challenge.inventory_hash,
            arguments_hash,
            &challenge.key_id,
            &challenge.challenge_id,
            challenge.created_at_unix_seconds,
        );
        let signature: Signature = signing_key.sign(message.as_bytes());
        let token = SignedAuditAuthorization {
            schema_version: MANAGER_AUTH_SCHEMA_VERSION,
            action,
            inventory_hash: challenge.inventory_hash,
            arguments_hash: arguments_hash.to_owned(),
            key_id: challenge.key_id,
            challenge_id: challenge.challenge_id,
            created_at_unix_seconds: challenge.created_at_unix_seconds,
            signature_der_hex: hex(signature.to_der().as_bytes()),
        };
        hex(&serde_json::to_vec(&token).unwrap())
    }

    fn sealed_recovery_token(root: &Path, signing_key: &SigningKey, module_id: &str) -> String {
        let challenge = manager_sealed_recovery_challenge(root, module_id).unwrap();
        let message = audit_authorization_message(
            challenge.action,
            &challenge.inventory_hash,
            &challenge.arguments_hash,
            &challenge.key_id,
            &challenge.challenge_id,
            challenge.created_at_unix_seconds,
        );
        let signature: Signature = signing_key.sign(message.as_bytes());
        let token = SignedAuditAuthorization {
            schema_version: MANAGER_AUTH_SCHEMA_VERSION,
            action: challenge.action,
            inventory_hash: challenge.inventory_hash,
            arguments_hash: challenge.arguments_hash,
            key_id: challenge.key_id,
            challenge_id: challenge.challenge_id,
            created_at_unix_seconds: challenge.created_at_unix_seconds,
            signature_der_hex: hex(signature.to_der().as_bytes()),
        };
        hex(&serde_json::to_vec(&token).unwrap())
    }

    fn begin_test_operation(
        root: &Path,
        action: AuditAction,
        targets: &[&str],
    ) -> AuthorizedAuditOperation {
        let manager = signing_key(29);
        register_manager_audit_auth_key(root, &public_key_hex(&manager), false).unwrap();
        let targets = targets
            .iter()
            .map(|target| (*target).to_owned())
            .collect::<Vec<_>>();
        let arguments_hash = hex(&Sha256::digest(
            serde_json::to_vec(&(action, &targets)).unwrap(),
        ));
        let token = authorization_token(root, &manager, action, &arguments_hash);
        begin_manager_audit_operation(root, &token, action, &arguments_hash, &targets).unwrap()
    }

    fn complete_test_operation_target(
        root: &Path,
        operation: &AuthorizedAuditOperation,
        action: AuditAction,
        target: &str,
    ) {
        complete_manager_audit_operation_target(root, &operation.operation_id, action, target)
            .unwrap();
    }

    fn checkpoint_envelope(root: &Path, signing_key: &SigningKey, generation: u64) -> String {
        let payload = checkpoint_payload(root).unwrap();
        checkpoint_envelope_for_payload(
            &serde_json::to_vec(&payload).unwrap(),
            signing_key,
            generation,
        )
    }

    fn checkpoint_envelope_for_payload(
        payload: &[u8],
        signing_key: &SigningKey,
        generation: u64,
    ) -> String {
        let payload_base64 = encode_base64(payload);
        let key_id = hex(&Sha256::digest(
            signing_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes(),
        ));
        let signable = format!(
            "{MANAGER_SEAL_SCHEMA_VERSION}\n{generation}\nandroid_keystore\nhardware\n{key_id}\n{payload_base64}"
        );
        let signature: Signature = signing_key.sign(signable.as_bytes());
        let envelope = ManagerCheckpointEnvelope {
            schema_version: MANAGER_SEAL_SCHEMA_VERSION,
            generation,
            key_backend: "android_keystore".to_owned(),
            key_protection: "hardware".to_owned(),
            key_id,
            payload: payload_base64,
            signature: encode_base64(signature.to_der().as_bytes()),
        };
        hex(&serde_json::to_vec(&envelope).unwrap())
    }

    #[test]
    fn records_and_verifies_an_authenticated_install_event() {
        let temp = TempDir::new().unwrap();
        let receipt = begin_install(temp.path(), report("test.module", "ab")).unwrap();
        let status = finish_install(
            temp.path(),
            receipt,
            InstallOutcome::InstallationFailed,
            Some("installer exited 1".to_owned()),
        )
        .unwrap();

        assert_eq!(status.verification, VerificationState::Verified);
        assert_eq!(status.event_count, 2);
        assert!(!status.high_risk);
        assert_ne!(status.head_hash, GENESIS_HASH);
        assert_eq!(list_modules(temp.path(), false).unwrap(), vec![status]);
        let history = read_module_history(temp.path(), "test.module", false).unwrap();
        assert_eq!(history.events.len(), 2);
        let AuditEventKind::InstallAccepted { report, .. } = &history.events[0].kind else {
            panic!("expected accepted-install event");
        };
        assert_eq!(report.findings[0].rule_id, "KSU-AUDIT-TEST-001");
        let AuditEventKind::InstallResult { outcome, error, .. } = &history.events[1].kind else {
            panic!("expected install-result event");
        };
        assert_eq!(*outcome, InstallOutcome::InstallationFailed);
        assert_eq!(error.as_deref(), Some("installer exited 1"));
    }

    #[test]
    fn sealed_prefix_drives_persistent_script_containment_plan() {
        let temp = TempDir::new().unwrap();
        let mut audit_report = report("persistent.module", "ab");
        audit_report.findings.push(Finding {
            rule_id: "KSU-AUDIT-PERSIST-001".to_owned(),
            severity: Severity::High,
            path: "/data/adb/service.d/persistent-module.sh".to_owned(),
            line: Some(4),
            title: "persistent startup script".to_owned(),
            evidence: "test".to_owned(),
            provenance: Vec::new(),
        });
        let receipt = begin_install(temp.path(), audit_report).unwrap();
        finish_install(temp.path(), receipt, InstallOutcome::Installed, None).unwrap();

        let manager = signing_key(31);
        register_manager_audit_auth_key(temp.path(), &public_key_hex(&manager), false).unwrap();
        commit_manager_audit_seal(temp.path(), &checkpoint_envelope(temp.path(), &manager, 1))
            .unwrap();
        std::fs::write(event_path(temp.path(), "persistent.module", 2), b"damaged").unwrap();
        std::fs::create_dir(
            module_path(temp.path(), "persistent.module")
                .join("events")
                .join("unexpected-entry"),
        )
        .unwrap();

        let plans = persistent_script_containment_plans(temp.path()).unwrap();
        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0].module_id, "persistent.module");
        assert_eq!(plans[0].paths, ["/data/adb/service.d/persistent-module.sh"]);
        assert!(!plans[0].infer_unattributed);
        assert!(module_requires_containment(temp.path(), "persistent.module").unwrap());
    }

    #[test]
    fn persistent_containment_result_is_authenticated_and_visible() {
        let temp = TempDir::new().unwrap();
        record(temp.path(), "contained.module", "ab");
        record_persistent_containment_result(
            temp.path(),
            "contained.module",
            true,
            &["/data/adb/service.d/unknown.sh".to_owned()],
            &["startup entry changed while being isolated".to_owned()],
        )
        .unwrap();

        let status = verify_module(temp.path(), "contained.module", false).unwrap();
        assert_eq!(status.quarantined_persistent_scripts, 1);
        assert_eq!(
            status.persistent_script_ownership,
            Some(PersistentScriptOwnership::Uncertain)
        );
        assert_eq!(
            status.quarantined_persistent_script_paths,
            ["/data/adb/service.d/unknown.sh"]
        );
        assert_eq!(
            status.persistent_script_failures,
            ["startup entry changed while being isolated"]
        );

        let path = persistent_containment_result_path(temp.path(), "contained.module");
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        value["record"]["failures"] = serde_json::json!([]);
        std::fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        assert!(verify_module(temp.path(), "contained.module", false).is_err());
    }

    #[test]
    fn first_sealed_event_loss_requires_unattributed_fallback() {
        let temp = TempDir::new().unwrap();
        record(temp.path(), "missing.module", "ab");
        let manager = signing_key(32);
        register_manager_audit_auth_key(temp.path(), &public_key_hex(&manager), false).unwrap();
        commit_manager_audit_seal(temp.path(), &checkpoint_envelope(temp.path(), &manager, 1))
            .unwrap();
        std::fs::remove_file(event_path(temp.path(), "missing.module", 1)).unwrap();

        let plans = persistent_script_containment_plans(temp.path()).unwrap();
        assert_eq!(plans.len(), 1);
        assert!(plans[0].paths.is_empty());
        assert!(plans[0].infer_unattributed);
    }

    #[test]
    fn containment_state_preserves_progress_but_reports_new_failures() {
        let temp = TempDir::new().unwrap();
        record(temp.path(), "contained.module", "ab");
        set_containment_state(
            temp.path(),
            "contained.module",
            ContainmentState::PersistentScriptsIncomplete,
        )
        .unwrap();
        set_containment_state(
            temp.path(),
            "contained.module",
            ContainmentState::PendingReboot,
        )
        .unwrap();
        let status = verify_module(temp.path(), "contained.module", false).unwrap();
        assert_eq!(
            status.containment_state,
            Some(ContainmentState::PersistentScriptsIncomplete)
        );

        set_containment_state(temp.path(), "contained.module", ContainmentState::Contained)
            .unwrap();
        set_containment_state(
            temp.path(),
            "contained.module",
            ContainmentState::PersistentScriptsIncomplete,
        )
        .unwrap();
        let status = verify_module(temp.path(), "contained.module", false).unwrap();
        assert_eq!(
            status.containment_state,
            Some(ContainmentState::PersistentScriptsIncomplete)
        );
        set_containment_state(temp.path(), "contained.module", ContainmentState::Contained)
            .unwrap();

        let path = module_containment_record_path(temp.path(), "contained.module");
        let mut record: AuthenticatedRecord<ModuleContainmentRecord> = read_json(&path).unwrap();
        record.record.state = ContainmentState::PendingReboot;
        atomic_write_json(&path, &record).unwrap();
        assert!(verify_module(temp.path(), "contained.module", false).is_err());
    }

    #[test]
    fn corrupted_suffix_is_quarantined_and_replaced_by_incident() {
        let temp = TempDir::new().unwrap();
        record(temp.path(), "test.module", "ab");
        record(temp.path(), "test.module", "cd");
        let second = event_path(temp.path(), "test.module", 2);
        let mut bytes = std::fs::read(&second).unwrap();
        let position = bytes.iter().position(|byte| *byte == b'c').unwrap();
        bytes[position] ^= 1;
        std::fs::write(&second, bytes).unwrap();

        assert!(verify_module(temp.path(), "test.module", false).is_err());
        let recovered = verify_module(temp.path(), "test.module", true).unwrap();
        assert_eq!(recovered.verification, VerificationState::Recovered);
        assert_eq!(recovered.event_count, 2);
        assert!(recovered.high_risk);
        assert!(
            module_path(temp.path(), "test.module")
                .join("quarantine")
                .exists()
        );
        assert_eq!(recovered.incidents.len(), 1);
    }

    #[test]
    fn recovery_is_isolated_to_the_affected_module() {
        let temp = TempDir::new().unwrap();
        record(temp.path(), "module.alpha", "ab");
        record(temp.path(), "module.beta", "cd");
        let alpha_event = event_path(temp.path(), "module.alpha", 1);
        std::fs::write(&alpha_event, b"not json").unwrap();

        let alpha = verify_module(temp.path(), "module.alpha", true).unwrap();
        let beta = verify_module(temp.path(), "module.beta", false).unwrap();
        assert!(alpha.high_risk);
        assert_eq!(alpha.event_count, 1);
        assert_eq!(beta.verification, VerificationState::Verified);
        assert_eq!(beta.event_count, 2);
        assert!(!beta.high_risk);
    }

    #[test]
    fn deleted_event_suffix_is_detected_by_manager_seal() {
        let temp = TempDir::new().unwrap();
        record(temp.path(), "test.module", "ab");
        record(temp.path(), "test.module", "cd");
        let manager = signing_key(7);
        register_manager_audit_auth_key(temp.path(), &public_key_hex(&manager), false).unwrap();
        commit_manager_audit_seal(temp.path(), &checkpoint_envelope(temp.path(), &manager, 1))
            .unwrap();
        std::fs::remove_file(event_path(temp.path(), "test.module", 4)).unwrap();

        assert!(verify_module(temp.path(), "test.module", true).is_err());
    }

    #[test]
    fn legacy_derived_metadata_is_ignored_and_removed() {
        let temp = TempDir::new().unwrap();
        record(temp.path(), "test.module", "ab");
        let revision = dashboard_store_revision(temp.path()).unwrap();
        let module = module_path(temp.path(), "test.module");
        std::fs::write(module.join("identity.json"), b"legacy identity").unwrap();
        std::fs::write(module.join("head.json"), b"legacy head").unwrap();
        std::fs::create_dir(temp.path().join("risk")).unwrap();
        std::fs::write(temp.path().join("risk/test.module.json"), b"legacy risk").unwrap();

        assert_eq!(dashboard_store_revision(temp.path()).unwrap(), revision);

        let status = verify_module(temp.path(), "test.module", true).unwrap();
        assert_eq!(status.verification, VerificationState::Verified);
        assert_eq!(status.event_count, 2);
        assert!(!status.high_risk);

        migrate_audit_store_v2(temp.path()).unwrap();
        assert!(!module.join("identity.json").exists());
        assert!(!module.join("head.json").exists());
        assert!(!temp.path().join("risk").exists());
        assert_eq!(dashboard_store_revision(temp.path()).unwrap(), revision);
    }

    #[test]
    fn missing_key_is_unavailable_not_treated_as_tampering() {
        let temp = TempDir::new().unwrap();
        record(temp.path(), "test.module", "ab");
        std::fs::remove_file(temp.path().join(KEY_FILE)).unwrap();

        let error = verify_module(temp.path(), "test.module", true).unwrap_err();
        assert!(error.to_string().contains("key is unavailable"));
        assert!(
            !module_path(temp.path(), "test.module")
                .join("quarantine")
                .exists()
        );
    }

    #[test]
    fn checkpoint_payload_contains_verified_module_heads() {
        let temp = TempDir::new().unwrap();
        let audit_root = temp.path().join("audit");
        let installed_root = temp.path().join("modules");
        let pending_root = temp.path().join("modules_update");
        let installed_module = installed_root.join("module.alpha");
        std::fs::create_dir_all(&installed_module).unwrap();
        std::fs::write(installed_module.join("module.prop"), b"id=module.alpha\n").unwrap();
        record(&audit_root, "module.beta", "ab");
        record(&audit_root, "module.alpha", "cd");

        let operation = begin_test_operation(&audit_root, AuditAction::Prune, &["module.beta"]);
        prune_stale_histories(
            &audit_root,
            &installed_root,
            &pending_root,
            &operation.operation_id,
        )
        .unwrap();
        complete_test_operation_target(&audit_root, &operation, AuditAction::Prune, "module.beta");
        finish_manager_audit_operation(&audit_root, &operation.operation_id).unwrap();

        let payload = checkpoint_payload(&audit_root).unwrap();
        assert_eq!(payload.modules.len(), 1);
        assert_eq!(payload.modules[0].module_id, "module.alpha");
        assert_eq!(payload.modules[0].event_hashes.len(), 2);
        assert_eq!(
            payload.modules[0].event_hashes.last(),
            Some(&payload.modules[0].head_hash)
        );
        assert_eq!(payload.tombstones.len(), 1);
        assert_eq!(payload.tombstones[0].module_id, "module.beta");
        assert_eq!(payload.tombstones[0].previous_event_count, 2);
        assert_eq!(payload.tombstones[0].previous_event_hashes.len(), 2);
        assert_eq!(
            payload.tombstones[0].previous_event_hashes.last(),
            Some(&payload.tombstones[0].previous_head_hash)
        );
        assert_eq!(payload.hmac_key_id.len(), 64);
        assert_eq!(payload.schema_version, CHECKPOINT_SCHEMA_VERSION);
        assert_eq!(payload.store_format_version, STORE_FORMAT_VERSION);
        assert_eq!(payload.inventory_hash.len(), 64);
        assert_eq!(
            checkpoint_payload(&audit_root).unwrap().inventory_hash,
            payload.inventory_hash
        );
    }

    #[test]
    fn manager_authorization_is_bound_to_action_arguments_and_inventory() {
        let temp = TempDir::new().unwrap();
        record(temp.path(), "test.module", "ab");
        let key = signing_key(7);
        let status =
            register_manager_audit_auth_key(temp.path(), &public_key_hex(&key), false).unwrap();
        assert!(status.configured);
        assert_eq!(
            status.key_id,
            Some(hex(&Sha256::digest(
                key.verifying_key().to_encoded_point(false).as_bytes()
            )))
        );

        let arguments_hash = "ab".repeat(32);
        let token = authorization_token(temp.path(), &key, AuditAction::Rescan, &arguments_hash);
        let targets = vec!["test.module".to_owned()];
        let operation = begin_manager_audit_operation(
            temp.path(),
            &token,
            AuditAction::Rescan,
            &arguments_hash,
            &targets,
        )
        .unwrap();
        assert!(
            begin_manager_audit_operation(
                temp.path(),
                &token,
                AuditAction::Prune,
                &arguments_hash,
                &targets,
            )
            .is_err()
        );
        assert!(
            begin_manager_audit_operation(
                temp.path(),
                &token,
                AuditAction::Rescan,
                &"cd".repeat(32),
                &targets,
            )
            .is_err()
        );

        let replay = begin_manager_audit_operation(
            temp.path(),
            &token,
            AuditAction::Rescan,
            &arguments_hash,
            &targets,
        )
        .unwrap();
        assert_eq!(replay.operation_id, operation.operation_id);

        let stale_token =
            authorization_token(temp.path(), &key, AuditAction::Rescan, &arguments_hash);
        record(temp.path(), "test.module", "cd");
        let error = begin_manager_audit_operation(
            temp.path(),
            &stale_token,
            AuditAction::Rescan,
            &arguments_hash,
            &targets,
        )
        .unwrap_err();
        assert!(error.to_string().contains("inventory changed"));
    }

    #[test]
    fn consumed_authorization_cannot_be_replayed_after_operation_loss() {
        let temp = TempDir::new().unwrap();
        record(temp.path(), "test.module", "ab");
        let manager = signing_key(7);
        register_manager_audit_auth_key(temp.path(), &public_key_hex(&manager), false).unwrap();
        let targets = vec!["test.module".to_owned()];
        let arguments_hash = "ab".repeat(32);
        let token =
            authorization_token(temp.path(), &manager, AuditAction::Rescan, &arguments_hash);
        let operation = begin_manager_audit_operation(
            temp.path(),
            &token,
            AuditAction::Rescan,
            &arguments_hash,
            &targets,
        )
        .unwrap();
        std::fs::remove_file(operation_path(temp.path(), &operation.operation_id)).unwrap();

        let error = begin_manager_audit_operation(
            temp.path(),
            &token,
            AuditAction::Rescan,
            &arguments_hash,
            &targets,
        )
        .unwrap_err();
        assert!(error.to_string().contains("already consumed"));
    }

    #[test]
    fn newer_challenge_invalidates_an_unconsumed_authorization() {
        let temp = TempDir::new().unwrap();
        record(temp.path(), "test.module", "ab");
        let manager = signing_key(7);
        register_manager_audit_auth_key(temp.path(), &public_key_hex(&manager), false).unwrap();
        let targets = vec!["test.module".to_owned()];
        let arguments_hash = "ab".repeat(32);
        let stale =
            authorization_token(temp.path(), &manager, AuditAction::Rescan, &arguments_hash);
        let current =
            authorization_token(temp.path(), &manager, AuditAction::Rescan, &arguments_hash);

        assert!(
            begin_manager_audit_operation(
                temp.path(),
                &stale,
                AuditAction::Rescan,
                &arguments_hash,
                &targets,
            )
            .is_err()
        );
        begin_manager_audit_operation(
            temp.path(),
            &current,
            AuditAction::Rescan,
            &arguments_hash,
            &targets,
        )
        .unwrap();
    }

    #[test]
    fn rescan_operation_recovers_event_written_before_progress() {
        let temp = TempDir::new().unwrap();
        record(temp.path(), "test.module", "ab");
        let operation = begin_test_operation(temp.path(), AuditAction::Rescan, &["test.module"]);
        append_event(
            temp.path(),
            "test.module",
            AuditEventKind::InstalledRescan {
                operation_id: operation.operation_id.clone(),
                report: report("test.module", "cd"),
            },
        )
        .unwrap();

        let payload = checkpoint_payload(temp.path()).unwrap();
        let interrupted = payload
            .operations
            .iter()
            .find(|candidate| candidate.operation_id == operation.operation_id)
            .unwrap();
        assert_eq!(interrupted.state, AuditOperationState::Applying);
        assert!(interrupted.completed_targets.is_empty());

        repair_audit_store(temp.path()).unwrap();
        let payload = checkpoint_payload(temp.path()).unwrap();
        let recovered = payload
            .operations
            .iter()
            .find(|candidate| candidate.operation_id == operation.operation_id)
            .unwrap();
        assert_eq!(recovered.state, AuditOperationState::Applied);
        assert_eq!(recovered.completed_targets, vec!["test.module"]);
        assert_eq!(
            read_module_history(temp.path(), "test.module", false)
                .unwrap()
                .events
                .len(),
            3
        );
    }

    #[test]
    fn interrupted_install_is_closed_once_without_rerunning_scripts() {
        let temp = TempDir::new().unwrap();
        begin_install(temp.path(), report("test.module", "ab")).unwrap();

        assert_eq!(
            recover_interrupted_installs(temp.path()).unwrap(),
            vec!["test.module"]
        );
        assert!(
            recover_interrupted_installs(temp.path())
                .unwrap()
                .is_empty()
        );
        let history = read_module_history(temp.path(), "test.module", false).unwrap();
        assert_eq!(history.events.len(), 2);
        let AuditEventKind::InstallResult { outcome, error, .. } = &history.events[1].kind else {
            panic!("expected interrupted install result");
        };
        assert_eq!(*outcome, InstallOutcome::InstallationFailed);
        assert!(error.as_deref().unwrap().contains("interrupted"));
    }

    #[test]
    fn manager_seal_authenticates_the_verified_event_prefix() {
        let temp = TempDir::new().unwrap();
        record(temp.path(), "test.module", "ab");
        let manager = signing_key(7);
        register_manager_audit_auth_key(temp.path(), &public_key_hex(&manager), false).unwrap();
        let before = checkpoint_payload(temp.path()).unwrap();
        let envelope = checkpoint_envelope(temp.path(), &manager, 1);
        let status = commit_manager_audit_seal(temp.path(), &envelope).unwrap();
        assert!(status.configured);
        assert_eq!(status.generation, Some(1));
        assert_eq!(manager_audit_seal_status(temp.path()).unwrap(), status);
        let after = checkpoint_payload(temp.path()).unwrap();
        assert_eq!(after.hmac_key_id, before.next_hmac_key_id);
        assert_eq!(after.next_hmac_key_id, after.hmac_key_id);
        assert!(!temp.path().join(NEXT_KEY_FILE).exists());
        assert_eq!(
            verify_module(temp.path(), "test.module", false)
                .unwrap()
                .manager_checkpoint,
            CheckpointState::Sealed
        );

        let key = load_key(temp.path(), false).unwrap();
        let path = event_path(temp.path(), "test.module", 1);
        let mut event: AuthenticatedEvent = read_json(&path).unwrap();
        event.event.timestamp_unix_seconds = event.event.timestamp_unix_seconds.saturating_add(1);
        let bytes = serde_json::to_vec(&event.event).unwrap();
        event.hmac_sha256 = hex(&hmac_sha256(&key, &bytes));
        event.event_hash = authenticated_event_hash(&bytes, &event.hmac_sha256);
        atomic_write_json(&path, &event).unwrap();

        let error = verify_module(temp.path(), "test.module", false).unwrap_err();
        assert!(error.to_string().contains("Manager-sealed"));
    }

    #[test]
    fn legacy_manager_seal_migrates_once_to_store_v2() {
        let temp = TempDir::new().unwrap();
        record(temp.path(), "test.module", "ab");
        let manager = signing_key(7);
        register_manager_audit_auth_key(temp.path(), &public_key_hex(&manager), false).unwrap();

        let mut legacy = checkpoint_payload(temp.path()).unwrap();
        legacy.schema_version = LEGACY_CHECKPOINT_SCHEMA_VERSION;
        legacy.store_format_version = LEGACY_STORE_FORMAT_VERSION;
        legacy.inventory_hash = checkpoint_inventory_hash(
            legacy.schema_version,
            legacy.store_format_version,
            &legacy.hmac_key_id,
            &legacy.next_hmac_key_id,
            &legacy.modules,
            &legacy.tombstones,
            &legacy.operations,
        )
        .unwrap();
        let mut legacy_json = serde_json::to_value(&legacy).unwrap();
        legacy_json
            .as_object_mut()
            .unwrap()
            .remove("store_format_version");
        let envelope_hex = checkpoint_envelope_for_payload(
            &serde_json::to_vec(&legacy_json).unwrap(),
            &manager,
            1,
        );
        let envelope_bytes = decode_hex(&envelope_hex).unwrap();
        let seal_hash = hex(&Sha256::digest(&envelope_bytes));
        atomic_write_json(
            &manager_seal_path(temp.path()),
            &StoredManagerSeal {
                envelope_hex,
                seal_hash: seal_hash.clone(),
            },
        )
        .unwrap();
        let key = read_key(temp.path()).unwrap();
        complete_hmac_rotation(temp.path(), &key, &legacy, &seal_hash).unwrap();

        let transition = verified_audit_snapshot(temp.path()).unwrap();
        assert_eq!(
            transition.inventory_relation,
            AuditInventoryRelation::AuthorizedTransition
        );
        assert_eq!(
            transition.checkpoint.schema_version,
            CHECKPOINT_SCHEMA_VERSION
        );
        assert_eq!(
            transition.checkpoint.store_format_version,
            STORE_FORMAT_VERSION
        );

        let status =
            commit_manager_audit_seal(temp.path(), &checkpoint_envelope(temp.path(), &manager, 2))
                .unwrap();
        assert_eq!(status.generation, Some(2));
        assert_eq!(
            verified_audit_snapshot(temp.path())
                .unwrap()
                .inventory_relation,
            AuditInventoryRelation::SealedCurrent
        );
    }

    #[test]
    fn manager_seal_detects_event_hmac_tampering() {
        let temp = TempDir::new().unwrap();
        record(temp.path(), "module.alpha", "ab");
        record(temp.path(), "module.beta", "cd");
        let manager = signing_key(7);
        register_manager_audit_auth_key(temp.path(), &public_key_hex(&manager), false).unwrap();
        commit_manager_audit_seal(temp.path(), &checkpoint_envelope(temp.path(), &manager, 1))
            .unwrap();

        let path = event_path(temp.path(), "module.alpha", 1);
        let mut event: AuthenticatedEvent = read_json(&path).unwrap();
        event.hmac_sha256.truncate(48);
        atomic_write_json(&path, &event).unwrap();

        let compromised = read_module_history_resilient(temp.path(), "module.alpha", true).unwrap();
        assert!(compromised.status.unresolved_risk);
        assert!(
            compromised
                .integrity_error
                .unwrap()
                .contains("authentication tag")
        );
        assert!(
            !verify_module(temp.path(), "module.beta", false)
                .unwrap()
                .unresolved_risk
        );
    }

    #[test]
    fn manager_seal_detects_same_length_event_hmac_replacement() {
        let temp = TempDir::new().unwrap();
        record(temp.path(), "test.module", "ab");
        let manager = signing_key(7);
        register_manager_audit_auth_key(temp.path(), &public_key_hex(&manager), false).unwrap();
        commit_manager_audit_seal(temp.path(), &checkpoint_envelope(temp.path(), &manager, 1))
            .unwrap();

        let path = event_path(temp.path(), "test.module", 1);
        let mut event: AuthenticatedEvent = read_json(&path).unwrap();
        event.hmac_sha256 = "0".repeat(64);
        atomic_write_json(&path, &event).unwrap();

        let compromised = read_module_history_resilient(temp.path(), "test.module", true).unwrap();
        assert!(compromised.status.unresolved_risk);
        assert!(
            compromised
                .integrity_error
                .unwrap()
                .contains("event hash mismatch")
        );
    }

    #[test]
    fn manager_seal_detects_noncanonical_event_encoding() {
        let temp = TempDir::new().unwrap();
        record(temp.path(), "test.module", "ab");
        let manager = signing_key(7);
        register_manager_audit_auth_key(temp.path(), &public_key_hex(&manager), false).unwrap();
        commit_manager_audit_seal(temp.path(), &checkpoint_envelope(temp.path(), &manager, 1))
            .unwrap();

        let path = event_path(temp.path(), "test.module", 1);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes.extend_from_slice(b" \n");
        std::fs::write(&path, bytes).unwrap();

        let compromised = read_module_history_resilient(temp.path(), "test.module", true).unwrap();
        assert!(compromised.status.unresolved_risk);
        assert!(
            compromised
                .integrity_error
                .unwrap()
                .contains("not canonical")
        );
    }

    #[test]
    fn sealed_damage_dashboard_snapshot_allows_containment_progress() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        record(root, "test.module", "ab");
        let manager = signing_key(7);
        register_manager_audit_auth_key(root, &public_key_hex(&manager), false).unwrap();
        let expected_checkpoint = checkpoint_payload(root).unwrap();
        let unsealed_snapshot = dashboard_checkpoint_snapshot(root).unwrap();
        assert!(unsealed_snapshot.integrity_failures.is_empty());
        assert_eq!(
            unsealed_snapshot.checkpoint.inventory_hash,
            expected_checkpoint.inventory_hash
        );
        commit_manager_audit_seal(root, &checkpoint_envelope(root, &manager, 1)).unwrap();

        let damaged = event_path(root, "test.module", 2);
        std::fs::write(&damaged, b"corrupt").unwrap();
        std::fs::write(
            damaged.with_extension("json.bak"),
            b"sealed evidence backup",
        )
        .unwrap();
        set_containment_state(root, "test.module", ContainmentState::PendingReboot).unwrap();
        set_containment_state(root, "test.module", ContainmentState::Contained).unwrap();

        let key = load_key(root, false).unwrap();
        assert_eq!(
            read_containment_state(root, "test.module", &key).unwrap(),
            Some(ContainmentState::Contained)
        );
        let snapshot = dashboard_checkpoint_snapshot(root).unwrap();
        assert_eq!(snapshot.integrity_failures.len(), 1);
        assert_eq!(snapshot.integrity_failures[0].module_id, "test.module");
        assert_eq!(
            snapshot.integrity_failures[0].cause,
            AuditIncidentCause::AuditEventInvalid
        );
        assert_eq!(
            snapshot.checkpoint.inventory_hash,
            expected_checkpoint.inventory_hash
        );
        assert_eq!(snapshot.checkpoint.modules, expected_checkpoint.modules);
    }

    #[test]
    fn containment_snapshot_scopes_stable_sealed_damage_to_its_module() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        record(root, "module.alpha", "ab");
        record(root, "module.beta", "cd");
        let manager = signing_key(7);
        register_manager_audit_auth_key(root, &public_key_hex(&manager), false).unwrap();
        commit_manager_audit_seal(root, &checkpoint_envelope(root, &manager, 1)).unwrap();

        std::fs::write(event_path(root, "module.alpha", 2), b"corrupt").unwrap();

        let (integrity, statuses) = containment_inventory_snapshot(root).unwrap();
        assert_eq!(integrity.failures.len(), 1);
        assert_eq!(integrity.failures[0].module_id, "module.alpha");
        assert_eq!(statuses.len(), 2);
        assert!(
            statuses
                .iter()
                .find(|status| status.module_id == "module.alpha")
                .unwrap()
                .unresolved_risk
        );
        assert!(
            !statuses
                .iter()
                .find(|status| status.module_id == "module.beta")
                .unwrap()
                .unresolved_risk
        );
    }

    #[test]
    fn verified_snapshot_accepts_manager_authorized_prune_transition() {
        let temp = TempDir::new().unwrap();
        let audit_root = temp.path().join("audit");
        let installed_root = temp.path().join("modules");
        let pending_root = temp.path().join("modules_update");
        std::fs::create_dir(&installed_root).unwrap();
        record(&audit_root, "stale.module", "ab");
        let manager = signing_key(29);
        register_manager_audit_auth_key(&audit_root, &public_key_hex(&manager), false).unwrap();
        commit_manager_audit_seal(&audit_root, &checkpoint_envelope(&audit_root, &manager, 1))
            .unwrap();

        let operation = begin_test_operation(&audit_root, AuditAction::Prune, &["stale.module"]);
        prune_stale_histories(
            &audit_root,
            &installed_root,
            &pending_root,
            &operation.operation_id,
        )
        .unwrap();
        complete_test_operation_target(&audit_root, &operation, AuditAction::Prune, "stale.module");
        finish_manager_audit_operation(&audit_root, &operation.operation_id).unwrap();

        let snapshot = verified_audit_snapshot(&audit_root).unwrap();
        assert_eq!(
            snapshot.inventory_relation,
            AuditInventoryRelation::AuthorizedTransition
        );
        assert!(snapshot.integrity_failures.is_empty());
        assert!(snapshot.histories.is_empty());
        assert!(snapshot.checkpoint.modules.is_empty());
        assert_eq!(snapshot.checkpoint.tombstones.len(), 1);
    }

    #[test]
    fn containment_snapshot_retries_transient_verification_failures() {
        let mut attempts = 0;
        let mut waits = 0;
        let snapshot = retry_verified_snapshot(
            || {
                attempts += 1;
                if attempts < 3 {
                    return Err(AuditSnapshotChanged.into());
                }
                Ok("stable")
            },
            || waits += 1,
        )
        .unwrap();

        assert_eq!(snapshot, "stable");
        assert_eq!(attempts, 3);
        assert_eq!(waits, 2);
    }

    #[test]
    fn containment_snapshot_exhausts_continuous_store_changes() {
        let mut attempts = 0;
        let mut waits = 0;
        let error = retry_verified_snapshot::<()>(
            || {
                attempts += 1;
                Err(AuditSnapshotChanged.into())
            },
            || waits += 1,
        )
        .unwrap_err();

        assert_eq!(attempts, VERIFIED_SNAPSHOT_ATTEMPTS);
        assert_eq!(waits, VERIFIED_SNAPSHOT_ATTEMPTS - 1);
        assert!(format!("{error:#}").contains("cannot obtain a stable module audit snapshot"));
    }

    #[test]
    fn containment_snapshot_does_not_retry_persistent_verification_failure() {
        let mut attempts = 0;
        let mut waits = 0;
        let error = retry_verified_snapshot::<()>(
            || {
                attempts += 1;
                bail!("Manager audit seal is invalid")
            },
            || waits += 1,
        )
        .unwrap_err();

        assert_eq!(attempts, 1);
        assert_eq!(waits, 0);
        assert!(format!("{error:#}").contains("Manager audit seal is invalid"));
    }

    #[test]
    fn manager_authorized_recovery_rebuilds_damage_with_an_unexpected_entry() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        record(root, "module.alpha", "ab");
        record(root, "module.beta", "cd");
        let manager = signing_key(7);
        register_manager_audit_auth_key(root, &public_key_hex(&manager), false).unwrap();
        commit_manager_audit_seal(root, &checkpoint_envelope(root, &manager, 1)).unwrap();

        let damaged_event = event_path(root, "module.alpha", 2);
        let unexpected_backup = damaged_event.with_extension("json.bak");
        std::fs::write(&damaged_event, b"corrupt").unwrap();
        std::fs::write(&unexpected_backup, b"untrusted backup").unwrap();
        let failure = sealed_integrity_status(root).unwrap();
        assert_eq!(failure.failures.len(), 1);
        assert_eq!(failure.failures[0].module_id, "module.alpha");
        assert_eq!(failure.failures[0].corrupted_from_sequence, 2);
        assert_eq!(
            failure.failures[0].cause,
            AuditIncidentCause::AuditEventInvalid
        );
        assert_eq!(
            failure.failures[0].unexpected_paths,
            vec![unexpected_backup.to_string_lossy().into_owned()]
        );
        assert!(verify_module(root, "module.alpha", true).is_err());
        let resilient = list_histories_resilient(root, true).unwrap();
        assert_eq!(resilient.len(), 2);
        let alpha = resilient
            .iter()
            .find(|history| history.status.module_id == "module.alpha")
            .unwrap();
        assert_eq!(alpha.status.verification, VerificationState::Compromised);
        assert!(alpha.status.unresolved_risk);
        assert!(alpha.events.is_empty());
        assert!(alpha.integrity_error.is_some());
        let beta = resilient
            .iter()
            .find(|history| history.status.module_id == "module.beta")
            .unwrap();
        assert_eq!(beta.status.verification, VerificationState::Verified);
        assert_eq!(beta.events.len(), 2);
        assert!(beta.integrity_error.is_none());
        let statuses = list_modules_resilient(root, true).unwrap();
        assert_eq!(statuses.len(), 2);
        assert_eq!(
            statuses
                .iter()
                .find(|status| status.module_id == "module.alpha")
                .unwrap()
                .verification,
            VerificationState::Compromised
        );
        assert_eq!(
            verify_module(root, "module.beta", false)
                .unwrap()
                .verification,
            VerificationState::Verified
        );

        let token = sealed_recovery_token(root, &manager, "module.alpha");
        let (recovered, receipt) =
            recover_manager_sealed_module(root, "module.alpha", &token).unwrap();
        assert!(recovered.unresolved_risk);
        assert_eq!(recovered.verification, VerificationState::Recovered);
        assert_eq!(
            receipt.state,
            crate::module_audit_transaction::AuditTransactionState::Committed
        );
        assert!(!unexpected_backup.exists());
        assert!(sealed_integrity_status(root).unwrap().failures.is_empty());

        let payload = checkpoint_payload(root).unwrap();
        let alpha = payload
            .modules
            .iter()
            .find(|module| module.module_id == "module.alpha")
            .unwrap();
        assert_eq!(alpha.sequence, 2);
        assert!(alpha.high_risk);
        assert!(payload.operations.iter().any(|operation| {
            operation.action == AuditAction::RecoverSealed
                && operation.targets == ["module.alpha"]
                && operation.state == AuditOperationState::Applied
        }));

        commit_manager_audit_seal(root, &checkpoint_envelope(root, &manager, 2)).unwrap();
        assert!(!sealed_recovery_path(root, "module.alpha").exists());
        assert!(
            verify_module(root, "module.alpha", false)
                .unwrap()
                .unresolved_risk
        );
        assert!(recover_manager_sealed_module(root, "module.alpha", &token).is_err());
    }

    #[test]
    fn sealed_recovery_resumes_after_authorization_record_is_persisted() {
        let temp = TempDir::new().unwrap();
        let root = temp.path();
        record(root, "test.module", "ab");
        let manager = signing_key(7);
        register_manager_audit_auth_key(root, &public_key_hex(&manager), false).unwrap();
        commit_manager_audit_seal(root, &checkpoint_envelope(root, &manager, 1)).unwrap();
        std::fs::write(event_path(root, "test.module", 2), b"corrupt").unwrap();

        let status = sealed_integrity_status(root).unwrap();
        let failure = status.failures[0].clone();
        let token_hex = sealed_recovery_token(root, &manager, "test.module");
        let token: SignedAuditAuthorization =
            serde_json::from_slice(&decode_hex(&token_hex).unwrap()).unwrap();
        let targets = vec!["test.module".to_owned()];
        let operation = begin_manager_audit_operation_at_inventory(
            root,
            &token_hex,
            AuditAction::RecoverSealed,
            &token.arguments_hash,
            &targets,
            Some(&status.inventory_hash),
        )
        .unwrap();
        let key = load_key(root, false).unwrap();
        write_record(
            &sealed_recovery_path(root, "test.module"),
            SealedRecoveryRecord {
                schema_version: SCHEMA_VERSION,
                module_id: "test.module".to_owned(),
                operation_id: operation.operation_id.clone(),
                seal_hash: status.seal_hash,
                base_inventory_hash: status.inventory_hash,
                corrupted_from_sequence: failure.corrupted_from_sequence,
                cause: failure.cause,
                reason: failure.reason.clone(),
                unexpected_paths: failure.unexpected_paths.clone(),
            },
            &key,
        )
        .unwrap();

        repair_audit_store(root).unwrap();
        let checkpoint = checkpoint_payload(root).unwrap();
        let operation = checkpoint
            .operations
            .iter()
            .find(|entry| entry.operation_id == operation.operation_id)
            .unwrap();
        assert_eq!(operation.state, AuditOperationState::Applied);
        assert_eq!(operation.completed_targets, targets);
        assert!(
            verify_module(root, "test.module", false)
                .unwrap()
                .unresolved_risk
        );
    }

    #[test]
    fn manager_seal_only_advances_from_the_previous_sealed_inventory() {
        let temp = TempDir::new().unwrap();
        record(temp.path(), "test.module", "ab");
        let manager = signing_key(7);
        register_manager_audit_auth_key(temp.path(), &public_key_hex(&manager), false).unwrap();
        let first = checkpoint_envelope(temp.path(), &manager, 1);
        let first_status = commit_manager_audit_seal(temp.path(), &first).unwrap();

        record(temp.path(), "test.module", "cd");
        let second = checkpoint_envelope(temp.path(), &manager, 2);
        let second_status = commit_manager_audit_seal(temp.path(), &second).unwrap();
        assert_ne!(first_status.seal_hash, second_status.seal_hash);
        assert_eq!(second_status.generation, Some(2));

        assert!(commit_manager_audit_seal(temp.path(), &first).is_err());
    }

    #[test]
    fn sealed_operation_receipt_cannot_disappear() {
        let temp = TempDir::new().unwrap();
        record(temp.path(), "test.module", "ab");
        let manager = signing_key(7);
        register_manager_audit_auth_key(temp.path(), &public_key_hex(&manager), false).unwrap();
        let targets = vec!["test.module".to_owned()];
        let arguments_hash = "ab".repeat(32);
        let token =
            authorization_token(temp.path(), &manager, AuditAction::Rescan, &arguments_hash);
        let operation = begin_manager_audit_operation(
            temp.path(),
            &token,
            AuditAction::Rescan,
            &arguments_hash,
            &targets,
        )
        .unwrap();
        record_installed_rescan(
            temp.path(),
            &operation.operation_id,
            "test.module",
            Ok(report("test.module", "cd")),
        )
        .unwrap();
        complete_test_operation_target(temp.path(), &operation, AuditAction::Rescan, "test.module");
        finish_manager_audit_operation(temp.path(), &operation.operation_id).unwrap();
        let first = checkpoint_envelope(temp.path(), &manager, 1);
        commit_manager_audit_seal(temp.path(), &first).unwrap();

        std::fs::remove_file(operation_path(temp.path(), &operation.operation_id)).unwrap();
        let error = verified_audit_snapshot(temp.path()).unwrap_err();
        assert!(format!("{error:#}").contains("operation disappeared"));
    }

    #[test]
    fn persisted_seal_recovers_an_interrupted_hmac_rotation() {
        let temp = TempDir::new().unwrap();
        record(temp.path(), "test.module", "ab");
        let manager = signing_key(7);
        register_manager_audit_auth_key(temp.path(), &public_key_hex(&manager), false).unwrap();
        let old_key = load_key(temp.path(), false).unwrap();
        let envelope_hex = checkpoint_envelope(temp.path(), &manager, 1);
        let envelope_bytes = decode_hex(&envelope_hex).unwrap();
        let envelope: ManagerCheckpointEnvelope = serde_json::from_slice(&envelope_bytes).unwrap();
        let registry = read_manager_auth_registry(temp.path(), &old_key)
            .unwrap()
            .unwrap();
        let payload = verify_manager_checkpoint_envelope(&envelope, &registry).unwrap();
        let seal_hash = hex(&Sha256::digest(&envelope_bytes));
        atomic_write_json(
            &manager_seal_path(temp.path()),
            &StoredManagerSeal {
                envelope_hex,
                seal_hash,
            },
        )
        .unwrap();
        let pending = pending_hmac_key(temp.path(), &old_key, false).unwrap();
        rewrite_authenticated_file::<ManagerAuditAuthRegistry>(
            &manager_auth_path(temp.path()),
            &old_key,
            &pending.next_key().unwrap(),
        )
        .unwrap();

        let recovered = load_key(temp.path(), false).unwrap();
        assert_eq!(hmac_key_id(&recovered), payload.next_hmac_key_id);
        assert!(!temp.path().join(NEXT_KEY_FILE).exists());
        assert_eq!(
            verify_module(temp.path(), "test.module", false)
                .unwrap()
                .manager_checkpoint,
            CheckpointState::Sealed
        );
    }

    #[test]
    fn manager_key_replacement_requires_explicit_recovery() {
        let temp = TempDir::new().unwrap();
        record(temp.path(), "test.module", "ab");
        let first = signing_key(7);
        let replacement = signing_key(9);
        register_manager_audit_auth_key(temp.path(), &public_key_hex(&first), false).unwrap();

        assert!(
            register_manager_audit_auth_key(temp.path(), &public_key_hex(&replacement), false,)
                .is_err()
        );
        let status =
            register_manager_audit_auth_key(temp.path(), &public_key_hex(&replacement), true)
                .unwrap();
        assert_eq!(
            status.key_id,
            Some(hex(&Sha256::digest(
                replacement
                    .verifying_key()
                    .to_encoded_point(false)
                    .as_bytes()
            )))
        );

        let arguments_hash = "ef".repeat(32);
        let targets = vec!["test.module".to_owned()];
        let stale_token =
            authorization_token(temp.path(), &first, AuditAction::Rescan, &arguments_hash);
        assert!(
            begin_manager_audit_operation(
                temp.path(),
                &stale_token,
                AuditAction::Rescan,
                &arguments_hash,
                &targets,
            )
            .is_err()
        );
        let replacement_token = authorization_token(
            temp.path(),
            &replacement,
            AuditAction::Rescan,
            &arguments_hash,
        );
        begin_manager_audit_operation(
            temp.path(),
            &replacement_token,
            AuditAction::Rescan,
            &arguments_hash,
            &targets,
        )
        .unwrap();
    }

    #[test]
    fn corrupted_manager_registry_can_only_be_replaced_by_recovery() {
        let temp = TempDir::new().unwrap();
        record(temp.path(), "test.module", "ab");
        let first = signing_key(7);
        let replacement = signing_key(9);
        register_manager_audit_auth_key(temp.path(), &public_key_hex(&first), false).unwrap();
        std::fs::write(manager_auth_path(temp.path()), b"corrupt registry").unwrap();

        assert!(manager_audit_auth_status(temp.path()).is_err());
        assert!(
            register_manager_audit_auth_key(temp.path(), &public_key_hex(&replacement), false,)
                .is_err()
        );
        let recovered =
            register_manager_audit_auth_key(temp.path(), &public_key_hex(&replacement), true)
                .unwrap();
        assert!(recovered.configured);
        assert_eq!(
            recovered.key_id,
            manager_audit_auth_status(temp.path()).unwrap().key_id
        );
    }

    #[test]
    fn installed_rescans_are_appended_to_the_authenticated_history() {
        let temp = TempDir::new().unwrap();
        let first = begin_test_operation(temp.path(), AuditAction::Rescan, &["test.module"]);
        let status = record_installed_rescan(
            temp.path(),
            &first.operation_id,
            "test.module",
            Ok(report("test.module", "ab")),
        )
        .unwrap();
        assert_eq!(status.event_count, 1);
        complete_test_operation_target(temp.path(), &first, AuditAction::Rescan, "test.module");
        finish_manager_audit_operation(temp.path(), &first.operation_id).unwrap();

        let second = begin_test_operation(temp.path(), AuditAction::Rescan, &["test.module"]);
        let status = record_installed_rescan(
            temp.path(),
            &second.operation_id,
            "test.module",
            Err("unable to read service.sh".to_owned()),
        )
        .unwrap();
        complete_test_operation_target(temp.path(), &second, AuditAction::Rescan, "test.module");
        finish_manager_audit_operation(temp.path(), &second.operation_id).unwrap();
        assert_eq!(status.event_count, 2);
        let history = read_module_history(temp.path(), "test.module", false).unwrap();
        assert!(matches!(
            history.events[0].kind,
            AuditEventKind::InstalledRescan { .. }
        ));
        assert!(matches!(
            history.events[1].kind,
            AuditEventKind::InstalledRescanFailed { .. }
        ));
    }

    #[test]
    fn transaction_commit_returns_an_idempotent_receipt() {
        let temp = TempDir::new().unwrap();
        record(temp.path(), "test.module", "ab");
        let manager = signing_key(29);
        register_manager_audit_auth_key(temp.path(), &public_key_hex(&manager), false).unwrap();
        let targets = vec!["test.module".to_owned()];
        let arguments_hash =
            manager_operation_arguments_hash(AuditAction::Rescan, &targets).unwrap();
        let token =
            authorization_token(temp.path(), &manager, AuditAction::Rescan, &arguments_hash);

        let mut transaction = crate::module_audit_transaction::AuditTransaction::begin(
            temp.path(),
            &token,
            AuditAction::Rescan,
            &arguments_hash,
            &targets,
        )
        .unwrap();
        record_installed_rescan(
            temp.path(),
            transaction.operation_id(),
            "test.module",
            Ok(report("test.module", "cd")),
        )
        .unwrap();
        transaction.complete_target("test.module").unwrap();
        let first = transaction.commit().unwrap();
        assert_eq!(
            first.state,
            crate::module_audit_transaction::AuditTransactionState::Committed
        );
        assert!(!first.replayed);
        assert_eq!(first.targets, targets);

        let replay = crate::module_audit_transaction::AuditTransaction::begin(
            temp.path(),
            &token,
            AuditAction::Rescan,
            &arguments_hash,
            &targets,
        )
        .unwrap();
        assert!(replay.is_committed());
        let second = replay.commit().unwrap();
        assert!(second.replayed);
        assert_eq!(second.operation_id, first.operation_id);
        assert_eq!(
            second.committed_store_revision,
            first.committed_store_revision
        );
        assert_eq!(
            second.committed_inventory_hash,
            first.committed_inventory_hash
        );
    }

    #[test]
    fn transaction_retry_recovers_side_effect_before_returning_receipt() {
        let temp = TempDir::new().unwrap();
        record(temp.path(), "test.module", "ab");
        let manager = signing_key(29);
        register_manager_audit_auth_key(temp.path(), &public_key_hex(&manager), false).unwrap();
        let targets = vec!["test.module".to_owned()];
        let arguments_hash =
            manager_operation_arguments_hash(AuditAction::Rescan, &targets).unwrap();
        let first_token =
            authorization_token(temp.path(), &manager, AuditAction::Rescan, &arguments_hash);
        let interrupted = crate::module_audit_transaction::AuditTransaction::begin(
            temp.path(),
            &first_token,
            AuditAction::Rescan,
            &arguments_hash,
            &targets,
        )
        .unwrap();
        record_installed_rescan(
            temp.path(),
            interrupted.operation_id(),
            "test.module",
            Ok(report("test.module", "cd")),
        )
        .unwrap();
        drop(interrupted);

        assert_eq!(
            active_manager_audit_operation_targets(temp.path(), AuditAction::Rescan).unwrap(),
            Some(targets.clone())
        );
        let retry_token =
            authorization_token(temp.path(), &manager, AuditAction::Rescan, &arguments_hash);
        let recovered = crate::module_audit_transaction::AuditTransaction::begin(
            temp.path(),
            &retry_token,
            AuditAction::Rescan,
            &arguments_hash,
            &targets,
        )
        .unwrap();
        assert!(recovered.is_committed());
        let receipt = recovered.commit().unwrap();
        assert!(receipt.replayed);
        assert_eq!(receipt.targets, targets);
    }

    #[test]
    fn stale_history_is_pruned_with_authenticated_tombstone() {
        let temp = TempDir::new().unwrap();
        let audit_root = temp.path().join("audit");
        let installed_root = temp.path().join("modules");
        let pending_root = temp.path().join("modules_update");
        std::fs::create_dir(&installed_root).unwrap();
        record(&audit_root, "stale.module", "ab");

        let stale = list_stale_histories(&audit_root, &installed_root, &pending_root).unwrap();
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0].module_id, "stale.module");
        assert_eq!(stale[0].event_count, 2);

        let operation = begin_test_operation(&audit_root, AuditAction::Prune, &["stale.module"]);
        let pruned = prune_stale_histories(
            &audit_root,
            &installed_root,
            &pending_root,
            &operation.operation_id,
        )
        .unwrap();
        complete_test_operation_target(&audit_root, &operation, AuditAction::Prune, "stale.module");
        finish_manager_audit_operation(&audit_root, &operation.operation_id).unwrap();
        assert_eq!(pruned.len(), 1);
        assert_eq!(pruned[0].removed_event_count, 2);
        assert!(!module_path(&audit_root, "stale.module").exists());
        assert!(list_histories(&audit_root, false).unwrap().is_empty());

        let tombstones = audit_root.join("tombstones/stale.module");
        let tombstone_path = std::fs::read_dir(tombstones)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let tombstone: AuthenticatedRecord<PrunedHistoryTombstone> =
            read_json(&tombstone_path).unwrap();
        let key = load_key(&audit_root, false).unwrap();
        verify_record(&tombstone.record, &tombstone.hmac_sha256, &key).unwrap();
        assert_eq!(tombstone.record.module_id, "stale.module");
        assert_eq!(tombstone.record.previous_event_count, 2);
        assert_eq!(
            tombstone.record.reason,
            format!("user_cleanup:{}", operation.operation_id)
        );

        std::fs::write(&tombstone_path, b"corrupt").unwrap();
        assert!(list_histories(&audit_root, false).is_err());
    }

    #[test]
    fn prune_operation_recovers_quarantine_written_before_progress() {
        let temp = TempDir::new().unwrap();
        let audit_root = temp.path().join("audit");
        let installed_root = temp.path().join("modules");
        let pending_root = temp.path().join("modules_update");
        std::fs::create_dir(&installed_root).unwrap();
        record(&audit_root, "stale.module", "ab");
        let key = load_key(&audit_root, false).unwrap();
        let operation = begin_test_operation(&audit_root, AuditAction::Prune, &["stale.module"]);
        prune_stale_histories(
            &audit_root,
            &installed_root,
            &pending_root,
            &operation.operation_id,
        )
        .unwrap();

        let trash_history =
            operation_trash_path(&audit_root, &operation.operation_id, "stale.module");
        let mut interrupted = read_operation(&audit_root, &operation.operation_id, &key)
            .unwrap()
            .unwrap();
        interrupted.completed_targets.clear();
        interrupted.state = AuditOperationState::Applying;
        interrupted.updated_at_unix_seconds = interrupted.started_at_unix_seconds;
        write_record(
            &operation_path(&audit_root, &operation.operation_id),
            interrupted,
            &key,
        )
        .unwrap();

        let payload = checkpoint_payload(&audit_root).unwrap();
        let interrupted = payload
            .operations
            .iter()
            .find(|candidate| candidate.operation_id == operation.operation_id)
            .unwrap();
        assert_eq!(interrupted.state, AuditOperationState::Applying);
        assert!(interrupted.completed_targets.is_empty());

        repair_audit_store(&audit_root).unwrap();
        let payload = checkpoint_payload(&audit_root).unwrap();
        let recovered = payload
            .operations
            .iter()
            .find(|candidate| candidate.operation_id == operation.operation_id)
            .unwrap();
        assert_eq!(recovered.state, AuditOperationState::Applied);
        assert_eq!(recovered.completed_targets, vec!["stale.module"]);
        assert!(trash_history.exists());
        let trash = audit_root
            .join(OPERATION_TRASH_DIR)
            .join(&operation.operation_id);
        assert!(trash.exists());
        let manager = signing_key(29);
        let envelope = checkpoint_envelope(&audit_root, &manager, 1);
        commit_manager_audit_seal(&audit_root, &envelope).unwrap();
        assert!(!trash.exists());

        std::fs::create_dir_all(&trash).unwrap();
        std::fs::write(trash.join("leftover"), b"test").unwrap();
        manager_audit_seal_status(&audit_root).unwrap();
        assert!(trash.exists());
        repair_audit_store(&audit_root).unwrap();
        assert!(!trash.exists());
    }

    #[test]
    fn installed_history_cannot_be_pruned() {
        let temp = TempDir::new().unwrap();
        let audit_root = temp.path().join("audit");
        let installed_root = temp.path().join("modules");
        let pending_root = temp.path().join("modules_update");
        let installed_module = installed_root.join("active.module");
        std::fs::create_dir_all(&installed_module).unwrap();
        std::fs::write(installed_module.join("module.prop"), b"id=active.module\n").unwrap();
        record(&audit_root, "active.module", "ab");

        assert!(
            list_stale_histories(&audit_root, &installed_root, &pending_root)
                .unwrap()
                .is_empty()
        );
        let operation = begin_test_operation(&audit_root, AuditAction::Prune, &["active.module"]);
        let error = prune_stale_histories(
            &audit_root,
            &installed_root,
            &pending_root,
            &operation.operation_id,
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("installed"),
            "unexpected error: {error:#}"
        );
        assert!(module_path(&audit_root, "active.module").exists());

        let pending_audit_root = temp.path().join("pending-audit");
        let pending_module = pending_root.join("pending.module");
        std::fs::create_dir_all(&pending_module).unwrap();
        std::fs::write(pending_module.join("module.prop"), b"id=pending.module\n").unwrap();
        record(&pending_audit_root, "pending.module", "cd");

        assert!(
            list_stale_histories(&pending_audit_root, &installed_root, &pending_root)
                .unwrap()
                .is_empty()
        );
        let operation =
            begin_test_operation(&pending_audit_root, AuditAction::Prune, &["pending.module"]);
        let error = prune_stale_histories(
            &pending_audit_root,
            &installed_root,
            &pending_root,
            &operation.operation_id,
        )
        .unwrap_err();
        assert!(error.to_string().contains("installed"));
        assert!(module_path(&pending_audit_root, "pending.module").exists());
    }

    #[test]
    fn pruning_retains_integrity_incident_in_tombstone() {
        let temp = TempDir::new().unwrap();
        let audit_root = temp.path().join("audit");
        let installed_root = temp.path().join("modules");
        let pending_root = temp.path().join("modules_update");
        std::fs::create_dir(&installed_root).unwrap();
        record(&audit_root, "risky.module", "ab");
        std::fs::write(event_path(&audit_root, "risky.module", 1), b"corrupt").unwrap();

        let operation = begin_test_operation(&audit_root, AuditAction::Prune, &["risky.module"]);
        let pruned = prune_stale_histories(
            &audit_root,
            &installed_root,
            &pending_root,
            &operation.operation_id,
        )
        .unwrap();
        assert!(pruned[0].retained_integrity_incident);
        let tombstone_path = std::fs::read_dir(audit_root.join("tombstones/risky.module"))
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let tombstone: AuthenticatedRecord<PrunedHistoryTombstone> =
            read_json(&tombstone_path).unwrap();
        assert!(tombstone.record.had_integrity_incident);
    }

    #[test]
    fn accepted_critical_install_does_not_require_secure_removal() {
        let temp = TempDir::new().unwrap();
        let audit_root = temp.path().join("audit");
        let mut critical = report("risky.module", "ab");
        critical.findings[0].severity = Severity::Critical;

        let receipt = begin_install(&audit_root, critical).unwrap();
        finish_install(&audit_root, receipt, InstallOutcome::Installed, None).unwrap();

        assert!(
            !module_requires_secure_removal(&audit_root, "risky.module").unwrap(),
            "an accepted static Critical finding must remain advisory"
        );
    }

    #[test]
    fn secure_removal_quarantines_module_without_running_its_scripts() {
        let temp = TempDir::new().unwrap();
        let audit_root = temp.path().join("audit");
        let installed_root = temp.path().join("modules");
        let pending_root = temp.path().join("modules_update");
        let module_root = installed_root.join("risky.module");
        let pending_module_root = pending_root.join("risky.module");
        std::fs::create_dir_all(&module_root).unwrap();
        std::fs::create_dir_all(&pending_module_root).unwrap();
        std::fs::write(module_root.join("module.prop"), b"id=risky.module\n").unwrap();
        std::fs::write(
            pending_module_root.join("module.prop"),
            b"id=risky.module\n",
        )
        .unwrap();
        std::fs::write(
            module_root.join("uninstall.sh"),
            b"touch /data/local/tmp/should-not-run\n",
        )
        .unwrap();

        let receipt = begin_install(&audit_root, report("risky.module", "ab")).unwrap();
        finish_install(&audit_root, receipt, InstallOutcome::Installed, None).unwrap();
        std::fs::write(event_path(&audit_root, "risky.module", 2), b"corrupt").unwrap();
        verify_module(&audit_root, "risky.module", true).unwrap();
        assert!(module_requires_secure_removal(&audit_root, "risky.module").unwrap());

        let rescan = begin_test_operation(&audit_root, AuditAction::Rescan, &["risky.module"]);
        record_installed_rescan(
            &audit_root,
            &rescan.operation_id,
            "risky.module",
            Ok(report("risky.module", "cd")),
        )
        .unwrap();
        complete_test_operation_target(&audit_root, &rescan, AuditAction::Rescan, "risky.module");
        finish_manager_audit_operation(&audit_root, &rescan.operation_id).unwrap();
        assert!(
            module_requires_secure_removal(&audit_root, "risky.module").unwrap(),
            "a later clean scan must not silently dismiss an integrity incident"
        );
        set_containment_state(&audit_root, "risky.module", ContainmentState::Contained).unwrap();

        let operation =
            begin_test_operation(&audit_root, AuditAction::SecureRemove, &["risky.module"]);
        let removed_paths = quarantine_module_for_secure_removal(
            &audit_root,
            &installed_root,
            &pending_root,
            &operation.operation_id,
            "risky.module",
        )
        .unwrap();
        assert!(!module_root.exists());
        assert!(!pending_module_root.exists());
        assert!(
            audit_root
                .join(OPERATION_TRASH_DIR)
                .join(&operation.operation_id)
                .join("module-content/installed/uninstall.sh")
                .exists()
        );
        assert!(
            audit_root
                .join(OPERATION_TRASH_DIR)
                .join(&operation.operation_id)
                .join("module-content/pending/module.prop")
                .exists()
        );

        let status = complete_secure_module_removal(
            &audit_root,
            &operation.operation_id,
            "risky.module",
            removed_paths,
        )
        .unwrap();
        assert!(!status.unresolved_risk);
        assert_eq!(status.containment_state, None);
        assert!(!module_requires_containment(&audit_root, "risky.module").unwrap());
        complete_test_operation_target(
            &audit_root,
            &operation,
            AuditAction::SecureRemove,
            "risky.module",
        );
        finish_manager_audit_operation(&audit_root, &operation.operation_id).unwrap();

        let manager = signing_key(29);
        commit_manager_audit_seal(&audit_root, &checkpoint_envelope(&audit_root, &manager, 1))
            .unwrap();
        assert!(
            !audit_root
                .join(OPERATION_TRASH_DIR)
                .join(operation.operation_id)
                .exists()
        );

        std::fs::create_dir_all(&module_root).unwrap();
        std::fs::write(module_root.join("module.prop"), b"id=risky.module\n").unwrap();
        let receipt = begin_install(&audit_root, report("risky.module", "ef")).unwrap();
        let status = finish_install(&audit_root, receipt, InstallOutcome::Installed, None).unwrap();
        assert!(!status.unresolved_risk);
        assert_eq!(status.containment_state, None);
        assert!(!module_requires_containment(&audit_root, "risky.module").unwrap());
    }

    #[test]
    fn operation_recovery_clears_completed_secure_removal_containment() {
        let temp = TempDir::new().unwrap();
        let audit_root = temp.path().join("audit");
        record(&audit_root, "risky.module", "ab");
        set_containment_state(&audit_root, "risky.module", ContainmentState::Contained).unwrap();
        let operation =
            begin_test_operation(&audit_root, AuditAction::SecureRemove, &["risky.module"]);

        append_event(
            &audit_root,
            "risky.module",
            AuditEventKind::SecureRemovalCompleted {
                operation_id: operation.operation_id.clone(),
                removed_paths: vec!["/data/adb/modules/risky.module".to_owned()],
            },
        )
        .unwrap();

        let checkpoint = checkpoint_payload(&audit_root).unwrap();
        let interrupted = checkpoint
            .operations
            .iter()
            .find(|candidate| candidate.operation_id == operation.operation_id)
            .unwrap();
        assert_eq!(interrupted.state, AuditOperationState::Applying);
        assert_eq!(
            verify_module(&audit_root, "risky.module", false)
                .unwrap()
                .containment_state,
            Some(ContainmentState::Contained)
        );

        repair_audit_store(&audit_root).unwrap();
        let checkpoint = checkpoint_payload(&audit_root).unwrap();
        let recovered = checkpoint
            .operations
            .iter()
            .find(|candidate| candidate.operation_id == operation.operation_id)
            .unwrap();
        assert_eq!(recovered.state, AuditOperationState::Applied);
        assert_eq!(recovered.completed_targets, ["risky.module"]);
        assert_eq!(
            verify_module(&audit_root, "risky.module", false)
                .unwrap()
                .containment_state,
            None
        );
    }

    #[test]
    fn no_backend_call_leaves_no_abort_record() {
        let temp = TempDir::new().unwrap();
        assert!(!temp.path().join(KEY_FILE).exists());
        assert!(!temp.path().join("modules").exists());
    }

    #[test]
    fn uninitialized_store_lists_as_empty_without_creating_files() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("audit");

        assert!(dashboard_store_uninitialized(&root).unwrap());
        assert!(list_histories(&root, true).unwrap().is_empty());
        assert!(!manager_audit_seal_status(&root).unwrap().configured);
        assert!(!root.exists());

        std::fs::create_dir(&root).unwrap();
        assert!(dashboard_store_uninitialized(&root).unwrap());
        std::fs::write(root.join(".lock"), b"").unwrap();
        assert!(dashboard_store_uninitialized(&root).unwrap());
        std::fs::write(root.join("unexpected"), b"").unwrap();
        assert!(!dashboard_store_uninitialized(&root).unwrap());
    }

    #[test]
    fn empty_store_initialization_never_adopts_existing_content() {
        let temp = TempDir::new().unwrap();
        let empty_root = temp.path().join("empty");
        initialize_empty_store(&empty_root).unwrap();
        assert!(empty_root.join(KEY_FILE).is_file());
        assert!(
            checkpoint_payload(&empty_root)
                .unwrap()
                .operations
                .is_empty()
        );

        let occupied_root = temp.path().join("occupied");
        std::fs::create_dir(&occupied_root).unwrap();
        std::fs::write(occupied_root.join("unexpected"), b"untrusted").unwrap();
        assert!(initialize_empty_store(&occupied_root).is_err());
        assert!(!occupied_root.join(KEY_FILE).exists());
    }

    #[test]
    fn dashboard_revision_detects_store_changes_without_creating_it() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("audit");
        let missing_revision = dashboard_store_revision(&root).unwrap();

        assert!(dashboard_module_ids(&root).unwrap().is_empty());
        assert!(!root.exists());

        record(&root, "test.module", "ab");
        let recorded_revision = dashboard_store_revision(&root).unwrap();
        assert_ne!(missing_revision, recorded_revision);

        record(&root, "test.module", "cd");
        assert_ne!(recorded_revision, dashboard_store_revision(&root).unwrap());
    }

    #[test]
    fn concurrent_writers_receive_distinct_sequences() {
        let temp = std::sync::Arc::new(TempDir::new().unwrap());
        let mut writers = Vec::new();
        for index in 0..8 {
            let temp = std::sync::Arc::clone(&temp);
            writers.push(std::thread::spawn(move || {
                record(
                    temp.path(),
                    "test.module",
                    if index % 2 == 0 { "ab" } else { "cd" },
                );
            }));
        }
        for writer in writers {
            writer.join().unwrap();
        }

        let status = verify_module(temp.path(), "test.module", false).unwrap();
        assert_eq!(status.event_count, 16);
        assert_eq!(status.verification, VerificationState::Verified);
    }

    #[test]
    fn hmac_matches_rfc_4231_test_vector() {
        let key = [0x0b_u8; 20];
        assert_eq!(
            hex(&hmac_sha256(&key, b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn manager_operation_hash_uses_the_authorization_contract() {
        let targets = vec!["first.module".to_owned(), "second.module".to_owned()];
        let expected = hex(&Sha256::digest(
            serde_json::to_vec(&(AuditAction::SecureRemove, &targets)).unwrap(),
        ));
        assert_eq!(
            manager_operation_arguments_hash(AuditAction::SecureRemove, &targets).unwrap(),
            expected
        );
    }
}
