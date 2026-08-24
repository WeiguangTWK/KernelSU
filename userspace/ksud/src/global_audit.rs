use anyhow::Result;
use std::path::Path;

use crate::{
    defs,
    module_audit_log::{
        AuditEventKind, CheckpointPayload, ManagerAuditAuthStatus, ManagerAuditSealStatus,
        ModuleAuditHistory, ModuleAuditStatus, SealedIntegrityStatus, VerifiedAuditSnapshot,
    },
};

pub const GLOBAL_AUDIT_MODULE_ID: &str = "kernelsu-global";

fn root() -> &'static Path {
    Path::new(defs::GLOBAL_AUDIT_DIR)
}

fn snapshot() -> Result<VerifiedAuditSnapshot> {
    crate::module_audit_log::verified_audit_snapshot(root())
}

pub fn record_event(kind: AuditEventKind) -> Result<()> {
    crate::module_audit_log::append_global_event(root(), GLOBAL_AUDIT_MODULE_ID, kind)
}

pub fn status() -> Result<ModuleAuditStatus> {
    history().map(|history| history.status)
}

pub fn history() -> Result<ModuleAuditHistory> {
    snapshot()?
        .histories
        .into_iter()
        .find(|history| history.status.module_id == GLOBAL_AUDIT_MODULE_ID)
        .ok_or_else(|| anyhow::anyhow!("global audit history is unavailable"))
}

pub fn checkpoint() -> Result<CheckpointPayload> {
    Ok(snapshot()?.checkpoint)
}

pub fn store_revision() -> Result<String> {
    crate::module_audit_log::dashboard_store_revision(root())
}

pub fn recovery_status() -> Result<SealedIntegrityStatus> {
    let snapshot = snapshot()?;
    Ok(SealedIntegrityStatus {
        seal_hash: snapshot
            .seal_status
            .seal_hash
            .ok_or_else(|| anyhow::anyhow!("Manager audit seal is not configured"))?,
        inventory_hash: snapshot
            .seal_status
            .inventory_hash
            .ok_or_else(|| anyhow::anyhow!("Manager audit seal inventory is unavailable"))?,
        failures: snapshot.integrity_failures,
    })
}

pub fn auth_status() -> Result<ManagerAuditAuthStatus> {
    Ok(snapshot()?.authorization_status)
}

pub fn register_auth_key(public_key: &str, recover: bool) -> Result<ManagerAuditAuthStatus> {
    crate::module_audit_log::register_manager_audit_auth_key(root(), public_key, recover)
}

pub fn seal_status() -> Result<ManagerAuditSealStatus> {
    Ok(snapshot()?.seal_status)
}

pub fn commit_seal(envelope: &str) -> Result<ManagerAuditSealStatus> {
    crate::module_audit_log::commit_manager_audit_seal(root(), envelope)
}
