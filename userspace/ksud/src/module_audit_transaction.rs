use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::module_audit_action::AuditAction;
use crate::module_audit_log;

const AUDIT_TRANSACTION_RECEIPT_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditTransactionState {
    Committed,
}

/// Durable ksud-side result of an authorized audit mutation.
///
/// The receipt describes the audit store immediately after the operation journal
/// reached its committed state. Manager sealing is a separate coordinator step
/// and may advance the store revision again.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditTransactionReceipt {
    pub schema_version: u32,
    pub operation_id: String,
    pub action: AuditAction,
    pub state: AuditTransactionState,
    pub replayed: bool,
    pub targets: Vec<String>,
    pub base_inventory_hash: String,
    pub committed_store_revision: String,
    pub committed_inventory_hash: String,
}

/// The only public execution boundary for Manager-authorized audit mutations.
///
/// Action implementations still own their domain side effects, but transaction
/// authorization, crash recovery, target progression and commit receipts flow
/// through this handle.
pub struct AuditTransaction {
    root: PathBuf,
    operation_id: String,
    action: AuditAction,
    targets: Vec<String>,
    completed_targets: Vec<String>,
    base_inventory_hash: String,
    replayed: bool,
    committed: bool,
}

impl AuditTransaction {
    pub fn begin(
        root: &Path,
        encoded_authorization: &str,
        action: AuditAction,
        arguments_hash: &str,
        targets: &[String],
    ) -> Result<Self> {
        Self::begin_at_inventory(
            root,
            encoded_authorization,
            action,
            arguments_hash,
            targets,
            None,
        )
    }

    pub(crate) fn begin_at_inventory(
        root: &Path,
        encoded_authorization: &str,
        action: AuditAction,
        arguments_hash: &str,
        targets: &[String],
        expected_inventory_hash: Option<&str>,
    ) -> Result<Self> {
        let operation = module_audit_log::begin_manager_audit_operation_at_inventory(
            root,
            encoded_authorization,
            action,
            arguments_hash,
            targets,
            expected_inventory_hash,
        )?;
        Ok(Self {
            root: root.to_owned(),
            operation_id: operation.operation_id,
            action,
            targets: operation.targets,
            completed_targets: operation.completed_targets,
            base_inventory_hash: operation.base_inventory_hash,
            replayed: operation.replayed,
            committed: operation.applied,
        })
    }

    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub fn is_committed(&self) -> bool {
        self.committed
    }

    pub fn pending_targets(&self) -> impl Iterator<Item = &str> {
        self.targets
            .iter()
            .filter(|target| !self.completed_targets.contains(*target))
            .map(String::as_str)
    }

    pub fn complete_target(&mut self, target: &str) -> Result<()> {
        ensure!(
            self.targets.iter().any(|candidate| candidate == target),
            "audit transaction target does not match"
        );
        if self
            .completed_targets
            .iter()
            .any(|completed| completed == target)
        {
            return Ok(());
        }
        module_audit_log::complete_manager_audit_operation_target(
            &self.root,
            &self.operation_id,
            self.action,
            target,
        )?;
        self.completed_targets.push(target.to_owned());
        self.completed_targets.sort();
        Ok(())
    }

    pub fn commit(mut self) -> Result<AuditTransactionReceipt> {
        if !self.committed {
            module_audit_log::finish_manager_audit_operation(&self.root, &self.operation_id)?;
            self.committed = true;
        }
        let snapshot = module_audit_log::verified_audit_snapshot(&self.root)?;
        Ok(AuditTransactionReceipt {
            schema_version: AUDIT_TRANSACTION_RECEIPT_SCHEMA_VERSION,
            operation_id: self.operation_id,
            action: self.action,
            state: AuditTransactionState::Committed,
            replayed: self.replayed,
            targets: self.targets,
            base_inventory_hash: self.base_inventory_hash,
            committed_store_revision: snapshot.store_revision,
            committed_inventory_hash: snapshot.checkpoint.inventory_hash,
        })
    }
}

pub fn arguments_hash(action: AuditAction, targets: &[String]) -> Result<String> {
    module_audit_log::manager_operation_arguments_hash(action, targets)
}

pub fn active_targets(root: &Path, action: AuditAction) -> Result<Option<Vec<String>>> {
    module_audit_log::active_manager_audit_operation_targets(root, action)
}
