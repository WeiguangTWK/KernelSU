use anyhow::{Context, Result, bail, ensure};
use ksu_module_audit::AuditReport;
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const SCHEMA_VERSION: u32 = 1;
const CHECKPOINT_SCHEMA_VERSION: u32 = 3;
const MANAGER_AUTH_SCHEMA_VERSION: u32 = 1;
const KEY_FILE: &str = ".hmac-key";
const MANAGER_AUTH_FILE: &str = "manager-auth.json";
const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
static ATTEMPT_COUNTER: AtomicU64 = AtomicU64::new(0);

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
        report: AuditReport,
    },
    InstalledRescanFailed {
        error: String,
    },
    IntegrityIncident {
        corrupted_from_sequence: u64,
        reason: String,
        quarantine: String,
    },
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
struct ModuleIdentity {
    schema_version: u32,
    module_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct RiskRecord {
    schema_version: u32,
    module_id: String,
    high_risk: bool,
    reason: String,
    updated_at_unix_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct HeadRecord {
    schema_version: u32,
    module_id: String,
    sequence: u64,
    head_hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(not(any(target_os = "android", test)), allow(dead_code))]
struct PrunedHistoryTombstone {
    schema_version: u32,
    module_id: String,
    cleared_at_unix_seconds: u64,
    previous_event_count: usize,
    previous_head_hash: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    previous_event_hashes: Vec<String>,
    had_integrity_incident: bool,
    reason: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct AuthenticatedRecord<T> {
    record: T,
    hmac_sha256: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationState {
    Verified,
    Recovered,
    Empty,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointState {
    NotConfigured,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ModuleAuditStatus {
    pub module_id: String,
    pub verification: VerificationState,
    pub high_risk: bool,
    pub event_count: usize,
    pub head_hash: String,
    pub hmac_verified: bool,
    pub manager_checkpoint: CheckpointState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ModuleAuditHistory {
    pub status: ModuleAuditStatus,
    pub events: Vec<AuditEvent>,
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

/// Canonical payload intended to be signed by the Manager's Android Keystore key.
/// Signature storage and verification deliberately remain a Manager integration concern.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CheckpointPayload {
    pub schema_version: u32,
    pub created_at_unix_seconds: u64,
    pub hmac_key_id: String,
    pub inventory_hash: String,
    pub modules: Vec<CheckpointModuleHead>,
    pub tombstones: Vec<CheckpointTombstone>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ManagerAuditAuthStatus {
    pub configured: bool,
    pub key_id: Option<String>,
    pub inventory_hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ManagerAuditAuthChallenge {
    pub schema_version: u32,
    pub action: String,
    pub inventory_hash: String,
    pub arguments_hash: String,
    pub key_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ManagerAuditAuthRegistry {
    schema_version: u32,
    public_key_hex: String,
    key_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct SignedAuditAuthorization {
    schema_version: u32,
    action: String,
    inventory_hash: String,
    arguments_hash: String,
    nonce_hex: String,
    signature_der_hex: String,
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
        options.read(true).write(true).create(true).truncate(false);
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

#[cfg_attr(not(any(target_os = "android", test)), allow(dead_code))]
pub fn record_installed_rescan(
    root: &Path,
    module_id: &str,
    result: std::result::Result<AuditReport, String>,
) -> Result<ModuleAuditStatus> {
    let _lock = AuditLock::acquire(root, true)?;
    validate_module_id(module_id)?;
    let kind = match result {
        Ok(report) => {
            ensure!(
                report.module_id.as_deref() == Some(module_id),
                "installed module id does not match module.prop"
            );
            AuditEventKind::InstalledRescan { report }
        }
        Err(error) => AuditEventKind::InstalledRescanFailed { error },
    };
    append_event(root, module_id, kind)?;
    verify_module_unlocked(root, module_id, true)
}

pub fn verify_module(root: &Path, module_id: &str, repair: bool) -> Result<ModuleAuditStatus> {
    let _lock = AuditLock::acquire(root, false)?;
    verify_module_unlocked(root, module_id, repair)
}

fn verify_module_unlocked(root: &Path, module_id: &str, repair: bool) -> Result<ModuleAuditStatus> {
    validate_module_id(module_id)?;
    let key = load_key(root, false)?;
    let identity_failure = verify_identity(root, module_id, &key).err();
    if let Some(error) = &identity_failure {
        ensure!(repair, "audit identity integrity failure: {error:#}");
    }
    let mut chain = verify_chain(root, module_id, &key, repair)?;
    if let Some(error) = identity_failure {
        let identity_path = module_path(root, module_id).join("identity.json");
        let quarantine = quarantine_auxiliary(root, module_id, &identity_path, "identity")?;
        ensure_identity(root, module_id, &key)?;
        append_incident(
            root,
            module_id,
            &key,
            &mut chain.events,
            0,
            format!("audit identity integrity failure: {error:#}"),
            &quarantine,
        )?;
        chain.state = VerificationState::Recovered;
    }
    let mut high_risk = chain
        .events
        .iter()
        .any(|entry| matches!(entry.event.kind, AuditEventKind::IntegrityIncident { .. }));
    match read_risk(root, module_id, &key) {
        Ok(Some(risk)) => high_risk |= risk.high_risk,
        Ok(None) => {}
        Err(error) => {
            ensure!(repair, "audit risk registry integrity failure: {error:#}");
            let risk_path = risk_path(root, module_id);
            let quarantine = quarantine_auxiliary(root, module_id, &risk_path, "risk")?;
            append_incident(
                root,
                module_id,
                &key,
                &mut chain.events,
                0,
                format!("audit risk registry integrity failure: {error:#}"),
                &quarantine,
            )?;
            chain.state = VerificationState::Recovered;
            high_risk = true;
        }
    }
    if high_risk {
        write_risk(root, module_id, &key, "audit history integrity failure")?;
    }
    let head_hash = chain
        .events
        .last()
        .map_or_else(|| GENESIS_HASH.to_owned(), |entry| entry.event_hash.clone());
    Ok(ModuleAuditStatus {
        module_id: module_id.to_owned(),
        verification: chain.state,
        high_risk,
        event_count: chain.events.len(),
        head_hash,
        hmac_verified: true,
        manager_checkpoint: CheckpointState::NotConfigured,
    })
}

pub fn list_modules(root: &Path, repair: bool) -> Result<Vec<ModuleAuditStatus>> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let key = load_key(root, false)?;
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

pub fn read_module_history(
    root: &Path,
    module_id: &str,
    repair: bool,
) -> Result<ModuleAuditHistory> {
    let _lock = AuditLock::acquire(root, false)?;
    verify_tombstones(root, &load_key(root, false)?)?;
    let status = verify_module_unlocked(root, module_id, repair)?;
    let key = load_key(root, false)?;
    let events = verify_chain(root, module_id, &key, false)?
        .events
        .into_iter()
        .map(|entry| entry.event)
        .collect::<Vec<_>>();
    Ok(ModuleAuditHistory { status, events })
}

pub fn list_histories(root: &Path, repair: bool) -> Result<Vec<ModuleAuditHistory>> {
    list_modules(root, repair)?
        .into_iter()
        .map(|status| read_module_history(root, &status.module_id, false))
        .collect()
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
    let _lock = AuditLock::acquire(root, false)?;
    verify_tombstones(root, &load_key(root, false)?)?;
    let mut stale = Vec::new();
    for module_id in audit_module_ids(&root.join("modules"))? {
        if installed_module_exists(installed_modules_root, pending_modules_root, &module_id) {
            continue;
        }
        let status = verify_module_unlocked(root, &module_id, true)?;
        stale.push(StaleAuditHistory {
            module_id,
            event_count: status.event_count,
            high_risk: status.high_risk,
        });
    }
    Ok(stale)
}

#[cfg_attr(not(any(target_os = "android", test)), allow(dead_code))]
pub fn prune_stale_histories(
    root: &Path,
    installed_modules_root: &Path,
    pending_modules_root: &Path,
    requested_module_id: Option<&str>,
) -> Result<Vec<PrunedAuditHistory>> {
    if !root.exists() || !root.join("modules").exists() {
        return Ok(Vec::new());
    }
    if let Some(module_id) = requested_module_id {
        validate_module_id(module_id)?;
    }
    let _lock = AuditLock::acquire(root, false)?;
    let key = load_key(root, false)?;
    verify_tombstones(root, &key)?;
    let mut module_ids = audit_module_ids(&root.join("modules"))?;
    if let Some(module_id) = requested_module_id {
        ensure!(
            module_ids.iter().any(|candidate| candidate == module_id),
            "module audit history not found"
        );
        module_ids.retain(|candidate| candidate == module_id);
    }

    let mut pruned = Vec::new();
    for module_id in module_ids {
        if installed_module_exists(installed_modules_root, pending_modules_root, &module_id) {
            ensure!(
                requested_module_id.is_none(),
                "cannot clear audit history for an installed module"
            );
            continue;
        }
        let status = verify_module_unlocked(root, &module_id, true)?;
        let event_hashes = verify_chain(root, &module_id, &key, false)?
            .events
            .into_iter()
            .map(|event| event.event_hash)
            .collect();
        // Recheck immediately before committing the authenticated tombstone to
        // narrow the race with a concurrent module installation.
        ensure!(
            !installed_module_exists(installed_modules_root, pending_modules_root, &module_id),
            "module was reinstalled while its audit history was being cleared"
        );
        let tombstone_path = new_tombstone_path(root, &module_id, &status.head_hash);
        let tombstone = PrunedHistoryTombstone {
            schema_version: SCHEMA_VERSION,
            module_id: module_id.clone(),
            cleared_at_unix_seconds: now(),
            previous_event_count: status.event_count,
            previous_head_hash: status.head_hash,
            previous_event_hashes: event_hashes,
            had_integrity_incident: status.high_risk,
            reason: "user_cleanup".to_owned(),
        };
        write_record(&tombstone_path, tombstone, &key)?;

        std::fs::remove_dir_all(module_path(root, &module_id))
            .with_context(|| format!("remove audit history for {module_id}"))?;
        let risk = risk_path(root, &module_id);
        if risk.exists() {
            std::fs::remove_file(&risk)
                .with_context(|| format!("remove compacted risk record for {module_id}"))?;
            sync_dir(risk.parent().context("risk record has no parent")?)?;
        }
        sync_dir(&root.join("modules"))?;
        pruned.push(PrunedAuditHistory {
            module_id,
            removed_event_count: status.event_count,
            retained_integrity_incident: status.high_risk,
        });
    }
    Ok(pruned)
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
            if !tombstone.record.previous_event_hashes.is_empty() {
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
            }
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
    let _lock = AuditLock::acquire(root, false)?;
    let key = load_key(root, false)?;
    let tombstones = verified_tombstones(root, &key)?
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
            .map(|module_id| verify_module_unlocked(root, &module_id, true))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .map(|status| {
                let event_hashes = verify_chain(root, &status.module_id, &key, false)?
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
    let hmac_key_id = hex(&Sha256::digest(key));
    let inventory_hash = checkpoint_inventory_hash(&hmac_key_id, &modules, &tombstones)?;
    Ok(CheckpointPayload {
        schema_version: CHECKPOINT_SCHEMA_VERSION,
        created_at_unix_seconds: now(),
        hmac_key_id,
        inventory_hash,
        modules,
        tombstones,
    })
}

fn checkpoint_inventory_hash(
    hmac_key_id: &str,
    modules: &[CheckpointModuleHead],
    tombstones: &[CheckpointTombstone],
) -> Result<String> {
    #[derive(Serialize)]
    struct Inventory<'a> {
        schema_version: u32,
        hmac_key_id: &'a str,
        modules: &'a [CheckpointModuleHead],
        tombstones: &'a [CheckpointTombstone],
    }

    let bytes = serde_json::to_vec(&Inventory {
        schema_version: CHECKPOINT_SCHEMA_VERSION,
        hmac_key_id,
        modules,
        tombstones,
    })?;
    Ok(hex(&Sha256::digest(bytes)))
}

pub fn manager_audit_auth_status(root: &Path) -> Result<ManagerAuditAuthStatus> {
    let checkpoint = checkpoint_payload(root)?;
    let _lock = AuditLock::acquire(root, false)?;
    let key = load_key(root, false)?;
    let registry = read_manager_auth_registry(root, &key)?;
    Ok(ManagerAuditAuthStatus {
        configured: registry.is_some(),
        key_id: registry.map(|registry| registry.key_id),
        inventory_hash: checkpoint.inventory_hash,
    })
}

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

pub fn manager_audit_auth_challenge(
    root: &Path,
    action: &str,
    arguments_hash: &str,
) -> Result<ManagerAuditAuthChallenge> {
    validate_authorization_field(action, "action")?;
    validate_sha256_hex(arguments_hash, "arguments hash")?;
    let status = manager_audit_auth_status(root)?;
    let key_id = status
        .key_id
        .context("Manager audit authorization key is not configured")?;
    Ok(ManagerAuditAuthChallenge {
        schema_version: MANAGER_AUTH_SCHEMA_VERSION,
        action: action.to_owned(),
        inventory_hash: status.inventory_hash,
        arguments_hash: arguments_hash.to_owned(),
        key_id,
    })
}

pub fn verify_manager_audit_authorization(
    root: &Path,
    encoded_authorization: &str,
    expected_action: &str,
    expected_arguments_hash: &str,
) -> Result<()> {
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
    ensure!(
        token.nonce_hex.len() == 64 && token.nonce_hex.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "invalid audit authorization nonce"
    );

    let checkpoint = checkpoint_payload(root)?;
    ensure!(
        token.inventory_hash == checkpoint.inventory_hash,
        "audit inventory changed after authorization"
    );
    let _lock = AuditLock::acquire(root, false)?;
    let hmac_key = load_key(root, false)?;
    let registry = read_manager_auth_registry(root, &hmac_key)?
        .context("Manager audit authorization key is not configured")?;
    let public_key = decode_hex(&registry.public_key_hex)?;
    let verifying_key =
        VerifyingKey::from_sec1_bytes(&public_key).context("invalid registered Manager key")?;
    let signature = Signature::from_der(&decode_hex(&token.signature_der_hex)?)
        .context("invalid Manager audit authorization signature")?;
    let message = audit_authorization_message(
        &token.action,
        &token.inventory_hash,
        &token.arguments_hash,
        &token.nonce_hex,
    );
    verifying_key
        .verify(message.as_bytes(), &signature)
        .context("Manager audit authorization signature rejected")
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

fn audit_authorization_message(
    action: &str,
    inventory_hash: &str,
    arguments_hash: &str,
    nonce_hex: &str,
) -> String {
    format!(
        "kernelsu-audit-authorization-v1\n{action}\n{inventory_hash}\n{arguments_hash}\n{nonce_hex}\n"
    )
}

fn validate_authorization_field(value: &str, name: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte == b'-'),
        "invalid audit authorization {name}"
    );
    Ok(())
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

fn manager_auth_path(root: &Path) -> PathBuf {
    root.join(MANAGER_AUTH_FILE)
}

#[cfg_attr(not(any(target_os = "android", test)), allow(dead_code))]
fn append_event(root: &Path, module_id: &str, kind: AuditEventKind) -> Result<()> {
    let key = load_key(root, true)?;
    if !module_path(root, module_id).exists() {
        ensure_identity(root, module_id, &key)?;
    }
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
        schema_version: SCHEMA_VERSION,
        module_id: module_id.to_owned(),
        sequence,
        timestamp_unix_seconds: now(),
        previous_hash,
        kind,
    };
    write_event(root, module_id, &key, event)
}

fn verify_chain(
    root: &Path,
    module_id: &str,
    key: &[u8; 32],
    repair: bool,
) -> Result<VerifiedChain> {
    let events_dir = module_path(root, module_id).join("events");
    if !events_dir.exists() {
        return Ok(VerifiedChain {
            events: Vec::new(),
            state: VerificationState::Empty,
        });
    }
    let mut paths = std::fs::read_dir(&events_dir)
        .context("read audit events")?
        .filter_map(std::result::Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect::<Vec<_>>();
    paths.sort();

    let mut valid = Vec::new();
    let mut failure = None;
    for (index, path) in paths.iter().enumerate() {
        let expected_sequence = u64::try_from(index).unwrap_or(u64::MAX).saturating_add(1);
        let result = verify_event_file(path, module_id, expected_sequence, &valid, key);
        match result {
            Ok(event) => valid.push(event),
            Err(error) => {
                failure = Some((index, expected_sequence, format!("{error:#}")));
                break;
            }
        }
    }

    let Some((bad_index, corrupted_from_sequence, reason)) = failure else {
        if !valid.is_empty() {
            match verify_head(root, module_id, key, &valid) {
                Ok(HeadState::Current) => {}
                Ok(HeadState::StaleButValid) => write_head(
                    root,
                    module_id,
                    key,
                    valid.last().context("non-empty audit chain has no head")?,
                )?,
                Err(error) => {
                    ensure!(repair, "audit head integrity failure: {error:#}");
                    let head_path = head_path(root, module_id);
                    let quarantine = quarantine_auxiliary(root, module_id, &head_path, "head")?;
                    append_incident(
                        root,
                        module_id,
                        key,
                        &mut valid,
                        0,
                        format!("audit head integrity failure: {error:#}"),
                        &quarantine,
                    )?;
                    write_risk(root, module_id, key, "audit history integrity failure")?;
                    return Ok(VerifiedChain {
                        events: valid,
                        state: VerificationState::Recovered,
                    });
                }
            }
        }
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

    let quarantine = quarantine_suffix(root, module_id, &paths[bad_index..])?;
    append_incident(
        root,
        module_id,
        key,
        &mut valid,
        corrupted_from_sequence,
        reason,
        &quarantine,
    )?;
    write_risk(root, module_id, key, "audit history integrity failure")?;
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
        schema_version: SCHEMA_VERSION,
        module_id: module_id.to_owned(),
        sequence,
        timestamp_unix_seconds: now(),
        previous_hash,
        kind: AuditEventKind::IntegrityIncident {
            corrupted_from_sequence,
            reason,
            quarantine: quarantine.to_string_lossy().into_owned(),
        },
    };
    write_event(root, module_id, key, incident)?;
    let path = event_path(root, module_id, sequence);
    events.push(verify_event_file(&path, module_id, sequence, events, key)?);
    Ok(())
}

fn verify_event_file(
    path: &Path,
    module_id: &str,
    expected_sequence: u64,
    preceding: &[AuthenticatedEvent],
    key: &[u8; 32],
) -> Result<AuthenticatedEvent> {
    let entry: AuthenticatedEvent = read_json(path)?;
    ensure!(
        entry.event.schema_version == SCHEMA_VERSION,
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
        constant_time_eq(
            entry.event_hash.as_bytes(),
            hex(&Sha256::digest(&bytes)).as_bytes()
        ),
        "event hash mismatch"
    );
    ensure!(
        constant_time_eq(
            entry.hmac_sha256.as_bytes(),
            hex(&hmac_sha256(key, &bytes)).as_bytes()
        ),
        "event authentication mismatch"
    );
    Ok(entry)
}

fn write_event(root: &Path, module_id: &str, key: &[u8; 32], event: AuditEvent) -> Result<()> {
    let bytes = serde_json::to_vec(&event)?;
    let entry = AuthenticatedEvent {
        event_hash: hex(&Sha256::digest(&bytes)),
        hmac_sha256: hex(&hmac_sha256(key, &bytes)),
        event,
    };
    let path = event_path(root, module_id, entry.event.sequence);
    ensure_dir(path.parent().context("event path has no parent")?)?;
    atomic_write_json(&path, &entry)?;
    write_head(root, module_id, key, &entry)
}

enum HeadState {
    Current,
    StaleButValid,
}

fn verify_head(
    root: &Path,
    module_id: &str,
    key: &[u8; 32],
    events: &[AuthenticatedEvent],
) -> Result<HeadState> {
    let path = head_path(root, module_id);
    let head: AuthenticatedRecord<HeadRecord> = read_json(&path)?;
    verify_record(&head.record, &head.hmac_sha256, key)?;
    ensure!(
        head.record.schema_version == SCHEMA_VERSION,
        "unsupported audit head schema"
    );
    ensure!(
        head.record.module_id == module_id,
        "audit head module id mismatch"
    );
    ensure!(head.record.sequence > 0, "invalid audit head sequence");
    let last = events.last().context("cannot verify an empty audit head")?;
    if head.record.sequence == last.event.sequence && head.record.head_hash == last.event_hash {
        return Ok(HeadState::Current);
    }
    if head.record.sequence < last.event.sequence {
        let index = usize::try_from(head.record.sequence.saturating_sub(1))?;
        if events
            .get(index)
            .is_some_and(|entry| entry.event_hash == head.record.head_hash)
        {
            return Ok(HeadState::StaleButValid);
        }
    }
    bail!("audit head does not match the verified event chain")
}

fn write_head(
    root: &Path,
    module_id: &str,
    key: &[u8; 32],
    entry: &AuthenticatedEvent,
) -> Result<()> {
    let record = HeadRecord {
        schema_version: SCHEMA_VERSION,
        module_id: module_id.to_owned(),
        sequence: entry.event.sequence,
        head_hash: entry.event_hash.clone(),
    };
    write_record(&head_path(root, module_id), record, key)
}

fn ensure_identity(root: &Path, module_id: &str, key: &[u8; 32]) -> Result<()> {
    let path = module_path(root, module_id).join("identity.json");
    if path.exists() {
        let identity: AuthenticatedRecord<ModuleIdentity> = read_json(&path)?;
        verify_record(&identity.record, &identity.hmac_sha256, key)?;
        ensure!(
            identity.record.schema_version == SCHEMA_VERSION,
            "unsupported audit identity schema"
        );
        ensure!(
            identity.record.module_id == module_id,
            "module audit identity mismatch"
        );
        return Ok(());
    }
    let record = ModuleIdentity {
        schema_version: SCHEMA_VERSION,
        module_id: module_id.to_owned(),
    };
    write_record(&path, record, key)
}

fn verify_identity(root: &Path, module_id: &str, key: &[u8; 32]) -> Result<()> {
    let path = module_path(root, module_id).join("identity.json");
    let identity: AuthenticatedRecord<ModuleIdentity> = read_json(&path)?;
    verify_record(&identity.record, &identity.hmac_sha256, key)?;
    ensure!(
        identity.record.schema_version == SCHEMA_VERSION,
        "unsupported audit identity schema"
    );
    ensure!(
        identity.record.module_id == module_id,
        "module audit identity mismatch"
    );
    Ok(())
}

fn write_risk(root: &Path, module_id: &str, key: &[u8; 32], reason: &str) -> Result<()> {
    let record = RiskRecord {
        schema_version: SCHEMA_VERSION,
        module_id: module_id.to_owned(),
        high_risk: true,
        reason: reason.to_owned(),
        updated_at_unix_seconds: now(),
    };
    write_record(&risk_path(root, module_id), record, key)
}

fn read_risk(root: &Path, module_id: &str, key: &[u8; 32]) -> Result<Option<RiskRecord>> {
    let path = risk_path(root, module_id);
    if !path.exists() {
        return Ok(None);
    }
    let risk: AuthenticatedRecord<RiskRecord> = read_json(&path)?;
    verify_record(&risk.record, &risk.hmac_sha256, key)?;
    ensure!(
        risk.record.schema_version == SCHEMA_VERSION,
        "unsupported risk record schema"
    );
    ensure!(
        risk.record.module_id == module_id,
        "risk record module id mismatch"
    );
    Ok(Some(risk.record))
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
    let head = head_path(root, module_id);
    if head.exists() {
        std::fs::rename(&head, directory.join("head.json"))
            .context("quarantine invalid audit head")?;
    }
    sync_dir(directory.parent().context("quarantine has no parent")?)?;
    Ok(directory)
}

fn quarantine_auxiliary(root: &Path, module_id: &str, path: &Path, label: &str) -> Result<PathBuf> {
    let directory = module_path(root, module_id)
        .join("quarantine")
        .join(format!("{}-{}", now(), std::process::id()));
    ensure_dir(&directory)?;
    let destination = directory.join(format!("{label}.json"));
    if path.exists() {
        std::fs::rename(path, &destination).context("quarantine corrupt audit metadata")?;
        sync_dir(path.parent().context("audit metadata has no parent")?)?;
    }
    Ok(destination)
}

fn load_key(root: &Path, create: bool) -> Result<[u8; 32]> {
    let path = root.join(KEY_FILE);
    if path.exists() {
        let mut key = [0_u8; 32];
        let mut file = File::open(&path).context("open module audit authentication key")?;
        file.read_exact(&mut key)
            .context("read module audit authentication key")?;
        let mut extra = [0_u8; 1];
        ensure!(
            file.read(&mut extra)? == 0,
            "invalid module audit authentication key length"
        );
        return Ok(key);
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

fn risk_path(root: &Path, module_id: &str) -> PathBuf {
    root.join("risk")
        .join(format!("{}.json", module_dir_name(module_id)))
}

#[cfg_attr(not(any(target_os = "android", test)), allow(dead_code))]
fn new_tombstone_path(root: &Path, module_id: &str, previous_head_hash: &str) -> PathBuf {
    root.join("tombstones")
        .join(module_dir_name(module_id))
        .join(format!("{}-{previous_head_hash}.json", now()))
}

fn head_path(root: &Path, module_id: &str) -> PathBuf {
    module_path(root, module_id).join("head.json")
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
        action: &str,
        arguments_hash: &str,
    ) -> String {
        let challenge = manager_audit_auth_challenge(root, action, arguments_hash).unwrap();
        let nonce_hex = "42".repeat(32);
        let message = audit_authorization_message(
            action,
            &challenge.inventory_hash,
            arguments_hash,
            &nonce_hex,
        );
        let signature: Signature = signing_key.sign(message.as_bytes());
        let token = SignedAuditAuthorization {
            schema_version: MANAGER_AUTH_SCHEMA_VERSION,
            action: action.to_owned(),
            inventory_hash: challenge.inventory_hash,
            arguments_hash: arguments_hash.to_owned(),
            nonce_hex,
            signature_der_hex: hex(signature.to_der().as_bytes()),
        };
        hex(&serde_json::to_vec(&token).unwrap())
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
        assert!(
            temp.path()
                .join("risk")
                .join(format!("{}.json", module_dir_name("test.module")))
                .exists()
        );
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
    fn deleted_event_suffix_is_detected_by_authenticated_head() {
        let temp = TempDir::new().unwrap();
        record(temp.path(), "test.module", "ab");
        record(temp.path(), "test.module", "cd");
        std::fs::remove_file(event_path(temp.path(), "test.module", 4)).unwrap();

        let status = verify_module(temp.path(), "test.module", true).unwrap();
        assert_eq!(status.verification, VerificationState::Recovered);
        assert_eq!(status.event_count, 4);
        assert!(status.high_risk);
    }

    #[test]
    fn stale_head_after_completed_event_is_healed_without_tamper_alarm() {
        let temp = TempDir::new().unwrap();
        record(temp.path(), "test.module", "ab");
        let key = load_key(temp.path(), false).unwrap();
        let first: AuthenticatedEvent =
            read_json(&event_path(temp.path(), "test.module", 1)).unwrap();
        record(temp.path(), "test.module", "cd");
        write_head(temp.path(), "test.module", &key, &first).unwrap();

        let status = verify_module(temp.path(), "test.module", true).unwrap();
        assert_eq!(status.verification, VerificationState::Verified);
        assert_eq!(status.event_count, 4);
        assert!(!status.high_risk);
        assert!(matches!(
            verify_head(
                temp.path(),
                "test.module",
                &key,
                &verify_chain(temp.path(), "test.module", &key, false)
                    .unwrap()
                    .events
            )
            .unwrap(),
            HeadState::Current
        ));
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

        prune_stale_histories(&audit_root, &installed_root, &pending_root, None).unwrap();

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
        let token = authorization_token(temp.path(), &key, "rescan", &arguments_hash);
        verify_manager_audit_authorization(temp.path(), &token, "rescan", &arguments_hash).unwrap();
        assert!(
            verify_manager_audit_authorization(temp.path(), &token, "prune", &arguments_hash,)
                .is_err()
        );
        assert!(
            verify_manager_audit_authorization(temp.path(), &token, "rescan", &"cd".repeat(32),)
                .is_err()
        );

        record(temp.path(), "test.module", "cd");
        let error =
            verify_manager_audit_authorization(temp.path(), &token, "rescan", &arguments_hash)
                .unwrap_err();
        assert!(error.to_string().contains("inventory changed"));
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
        let stale_token = authorization_token(temp.path(), &first, "rescan", &arguments_hash);
        assert!(
            verify_manager_audit_authorization(
                temp.path(),
                &stale_token,
                "rescan",
                &arguments_hash,
            )
            .is_err()
        );
        let replacement_token =
            authorization_token(temp.path(), &replacement, "rescan", &arguments_hash);
        verify_manager_audit_authorization(
            temp.path(),
            &replacement_token,
            "rescan",
            &arguments_hash,
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
    fn checkpoint_accepts_legacy_tombstone_without_event_hashes() {
        #[derive(Serialize)]
        struct LegacyTombstone {
            schema_version: u32,
            module_id: String,
            cleared_at_unix_seconds: u64,
            previous_event_count: usize,
            previous_head_hash: String,
            had_integrity_incident: bool,
            reason: String,
        }

        let temp = TempDir::new().unwrap();
        record(temp.path(), "active.module", "ab");
        let key = load_key(temp.path(), false).unwrap();
        let legacy = LegacyTombstone {
            schema_version: SCHEMA_VERSION,
            module_id: "legacy.module".to_owned(),
            cleared_at_unix_seconds: 1,
            previous_event_count: 3,
            previous_head_hash: "ab".repeat(32),
            had_integrity_incident: false,
            reason: "user_cleanup".to_owned(),
        };
        let bytes = serde_json::to_vec(&legacy).unwrap();
        let authenticated = AuthenticatedRecord {
            record: legacy,
            hmac_sha256: hex(&hmac_sha256(&key, &bytes)),
        };
        let path = temp.path().join("tombstones/legacy.module/legacy.json");
        ensure_dir(path.parent().unwrap()).unwrap();
        atomic_write_json(&path, &authenticated).unwrap();

        let payload = checkpoint_payload(temp.path()).unwrap();
        assert_eq!(payload.tombstones.len(), 1);
        assert!(payload.tombstones[0].previous_event_hashes.is_empty());
    }

    #[test]
    fn installed_rescans_are_appended_to_the_authenticated_history() {
        let temp = TempDir::new().unwrap();
        let status =
            record_installed_rescan(temp.path(), "test.module", Ok(report("test.module", "ab")))
                .unwrap();
        assert_eq!(status.event_count, 1);

        let status = record_installed_rescan(
            temp.path(),
            "test.module",
            Err("unable to read service.sh".to_owned()),
        )
        .unwrap();
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
    fn corrupted_risk_registry_is_recovered_and_recorded() {
        let temp = TempDir::new().unwrap();
        record(temp.path(), "test.module", "ab");
        let event = event_path(temp.path(), "test.module", 1);
        std::fs::write(&event, b"corrupt event").unwrap();
        verify_module(temp.path(), "test.module", true).unwrap();
        let risk = risk_path(temp.path(), "test.module");
        std::fs::write(&risk, b"corrupt risk").unwrap();

        let status = verify_module(temp.path(), "test.module", true).unwrap();
        assert_eq!(status.verification, VerificationState::Recovered);
        assert_eq!(status.event_count, 2);
        assert!(status.high_risk);
        assert!(
            read_risk(
                temp.path(),
                "test.module",
                &load_key(temp.path(), false).unwrap()
            )
            .unwrap()
            .unwrap()
            .high_risk
        );
    }

    #[test]
    fn corrupted_identity_is_recovered_and_recorded() {
        let temp = TempDir::new().unwrap();
        record(temp.path(), "test.module", "ab");
        let identity = module_path(temp.path(), "test.module").join("identity.json");
        std::fs::write(&identity, b"corrupt identity").unwrap();

        let status = verify_module(temp.path(), "test.module", true).unwrap();
        assert_eq!(status.verification, VerificationState::Recovered);
        assert_eq!(status.event_count, 3);
        assert!(status.high_risk);
        verify_identity(
            temp.path(),
            "test.module",
            &load_key(temp.path(), false).unwrap(),
        )
        .unwrap();
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

        let pruned = prune_stale_histories(
            &audit_root,
            &installed_root,
            &pending_root,
            Some("stale.module"),
        )
        .unwrap();
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
        assert_eq!(tombstone.record.reason, "user_cleanup");

        std::fs::write(&tombstone_path, b"corrupt").unwrap();
        assert!(list_histories(&audit_root, false).is_err());
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
        let error = prune_stale_histories(
            &audit_root,
            &installed_root,
            &pending_root,
            Some("active.module"),
        )
        .unwrap_err();
        assert!(error.to_string().contains("installed module"));
        assert!(module_path(&audit_root, "active.module").exists());

        let pending_module = pending_root.join("pending.module");
        std::fs::create_dir_all(&pending_module).unwrap();
        std::fs::write(pending_module.join("module.prop"), b"id=pending.module\n").unwrap();
        record(&audit_root, "pending.module", "cd");

        assert!(
            list_stale_histories(&audit_root, &installed_root, &pending_root)
                .unwrap()
                .is_empty()
        );
        let error = prune_stale_histories(
            &audit_root,
            &installed_root,
            &pending_root,
            Some("pending.module"),
        )
        .unwrap_err();
        assert!(error.to_string().contains("installed module"));
        assert!(module_path(&audit_root, "pending.module").exists());
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

        let pruned = prune_stale_histories(
            &audit_root,
            &installed_root,
            &pending_root,
            Some("risky.module"),
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
    fn no_backend_call_leaves_no_abort_record() {
        let temp = TempDir::new().unwrap();
        assert!(!temp.path().join(KEY_FILE).exists());
        assert!(!temp.path().join("modules").exists());
    }

    #[test]
    fn uninitialized_store_lists_as_empty_without_creating_files() {
        let temp = TempDir::new().unwrap();
        let root = temp.path().join("audit");

        assert!(list_histories(&root, true).unwrap().is_empty());
        assert!(!root.exists());
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
}
