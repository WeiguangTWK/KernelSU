use anyhow::Result;
use std::path::Path;

use crate::{
    defs,
    module_audit_log::{
        AuditEventKind, CheckpointPayload, ManagerAuditAuthStatus, ManagerAuditSealStatus,
        ModuleAuditHistory, ModuleAuditStatus, SealedIntegrityStatus,
    },
};

pub const GLOBAL_AUDIT_MODULE_ID: &str = "kernelsu-global";

fn root() -> &'static Path {
    Path::new(defs::GLOBAL_AUDIT_DIR)
}

pub fn record_event(kind: AuditEventKind) -> Result<()> {
    crate::module_audit_log::append_global_event(root(), GLOBAL_AUDIT_MODULE_ID, kind)
}

pub fn status() -> Result<ModuleAuditStatus> {
    crate::module_audit_log::read_module_history_resilient(root(), GLOBAL_AUDIT_MODULE_ID, true)
        .map(|history| history.status)
}

pub fn history() -> Result<ModuleAuditHistory> {
    crate::module_audit_log::read_module_history_resilient(root(), GLOBAL_AUDIT_MODULE_ID, true)
}

pub fn checkpoint() -> Result<CheckpointPayload> {
    crate::module_audit_log::checkpoint_payload(root())
}

pub fn recovery_status() -> Result<SealedIntegrityStatus> {
    crate::module_audit_log::sealed_integrity_status(root())
}

pub fn auth_status() -> Result<ManagerAuditAuthStatus> {
    crate::module_audit_log::manager_audit_auth_status(root())
}

pub fn register_auth_key(public_key: &str, recover: bool) -> Result<ManagerAuditAuthStatus> {
    crate::module_audit_log::register_manager_audit_auth_key(root(), public_key, recover)
}

pub fn seal_status() -> Result<ManagerAuditSealStatus> {
    crate::module_audit_log::manager_audit_seal_status(root())
}

pub fn commit_seal(envelope: &str) -> Result<ManagerAuditSealStatus> {
    crate::module_audit_log::commit_manager_audit_seal(root(), envelope)
}
