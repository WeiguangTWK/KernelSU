use anyhow::Result;
#[cfg(target_os = "android")]
use anyhow::ensure;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
#[cfg(target_os = "android")]
use std::path::Path;
use std::str::FromStr;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum AuditAction {
    Rescan,
    Prune,
    SecureRemove,
    RecoverSealed,
    CloseIncident,
    DeleteQuarantinedScript,
    RetryScriptContainment,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditChallengeTarget {
    None,
    OptionalModule,
    Module,
    ModuleAndIncident,
    Incident,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditOperationRecovery {
    RescanEvent,
    PruneArtifacts,
    SecureRemovalEvent,
    SealedRecoveryRecord,
    IncidentCloseEvent,
    QuarantinedScriptState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditAuthorizationInventory {
    /// Authorize against a fully verified current checkpoint payload.
    CurrentCheckpoint,
    /// Authorize recovery against the active Manager seal and its diagnosed damage.
    ManagerSealedDamage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditActionDescriptor {
    pub action: AuditAction,
    pub wire_name: &'static str,
    pub route_name: &'static str,
    pub challenge_target: AuditChallengeTarget,
    pub authorization_inventory: AuditAuthorizationInventory,
    pub recovery: AuditOperationRecovery,
    pub finalizes_operation_trash: bool,
}

const ACTION_DESCRIPTORS: [AuditActionDescriptor; 7] = [
    AuditActionDescriptor {
        action: AuditAction::Rescan,
        wire_name: "rescan",
        route_name: "rescan",
        challenge_target: AuditChallengeTarget::None,
        authorization_inventory: AuditAuthorizationInventory::CurrentCheckpoint,
        recovery: AuditOperationRecovery::RescanEvent,
        finalizes_operation_trash: false,
    },
    AuditActionDescriptor {
        action: AuditAction::Prune,
        wire_name: "prune",
        route_name: "prune",
        challenge_target: AuditChallengeTarget::OptionalModule,
        authorization_inventory: AuditAuthorizationInventory::CurrentCheckpoint,
        recovery: AuditOperationRecovery::PruneArtifacts,
        finalizes_operation_trash: true,
    },
    AuditActionDescriptor {
        action: AuditAction::SecureRemove,
        wire_name: "secure-remove",
        route_name: "secure_remove_module",
        challenge_target: AuditChallengeTarget::Module,
        authorization_inventory: AuditAuthorizationInventory::CurrentCheckpoint,
        recovery: AuditOperationRecovery::SecureRemovalEvent,
        finalizes_operation_trash: true,
    },
    AuditActionDescriptor {
        action: AuditAction::RecoverSealed,
        wire_name: "recover-sealed",
        route_name: "recover_sealed_history",
        challenge_target: AuditChallengeTarget::Module,
        authorization_inventory: AuditAuthorizationInventory::ManagerSealedDamage,
        recovery: AuditOperationRecovery::SealedRecoveryRecord,
        finalizes_operation_trash: false,
    },
    AuditActionDescriptor {
        action: AuditAction::CloseIncident,
        wire_name: "close-incident",
        route_name: "close_incident",
        challenge_target: AuditChallengeTarget::ModuleAndIncident,
        authorization_inventory: AuditAuthorizationInventory::CurrentCheckpoint,
        recovery: AuditOperationRecovery::IncidentCloseEvent,
        finalizes_operation_trash: false,
    },
    AuditActionDescriptor {
        action: AuditAction::DeleteQuarantinedScript,
        wire_name: "delete-quarantined-script",
        route_name: "delete_quarantined_script",
        challenge_target: AuditChallengeTarget::Incident,
        authorization_inventory: AuditAuthorizationInventory::CurrentCheckpoint,
        recovery: AuditOperationRecovery::QuarantinedScriptState,
        finalizes_operation_trash: false,
    },
    AuditActionDescriptor {
        action: AuditAction::RetryScriptContainment,
        wire_name: "retry-script-containment",
        route_name: "retry_script_containment",
        challenge_target: AuditChallengeTarget::Incident,
        authorization_inventory: AuditAuthorizationInventory::CurrentCheckpoint,
        recovery: AuditOperationRecovery::QuarantinedScriptState,
        finalizes_operation_trash: false,
    },
];

impl AuditAction {
    pub const fn descriptor(self) -> &'static AuditActionDescriptor {
        &ACTION_DESCRIPTORS[self as usize]
    }

    pub const fn wire_name(self) -> &'static str {
        self.descriptor().wire_name
    }

    pub const fn route_name(self) -> &'static str {
        self.descriptor().route_name
    }

    #[cfg(target_os = "android")]
    fn validate_challenge_target(
        self,
        module_id: Option<&str>,
        incident_id: Option<&str>,
    ) -> Result<()> {
        use AuditChallengeTarget::{Incident, Module, ModuleAndIncident, None, OptionalModule};

        let valid = match self.descriptor().challenge_target {
            None => module_id.is_none() && incident_id.is_none(),
            OptionalModule => incident_id.is_none(),
            Module => module_id.is_some() && incident_id.is_none(),
            ModuleAndIncident => module_id.is_some() && incident_id.is_some(),
            Incident => module_id.is_none() && incident_id.is_some(),
        };
        ensure!(
            valid,
            "invalid authorization target for audit action {}",
            self.wire_name()
        );
        Ok(())
    }
}

impl fmt::Display for AuditAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.wire_name())
    }
}

impl FromStr for AuditAction {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        ACTION_DESCRIPTORS
            .iter()
            .find(|descriptor| descriptor.wire_name == value)
            .map(|descriptor| descriptor.action)
            .ok_or_else(|| anyhow::anyhow!("unsupported audit action: {value}"))
    }
}

impl Serialize for AuditAction {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.wire_name())
    }
}

impl<'de> Deserialize<'de> for AuditAction {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(target_os = "android")]
pub fn manager_authorization_challenge(
    root: &Path,
    action: AuditAction,
    module_id: Option<&str>,
    incident_id: Option<&str>,
) -> Result<crate::module_audit_log::ManagerAuditAuthChallenge> {
    action.validate_challenge_target(module_id, incident_id)?;
    let arguments_hash = match action {
        AuditAction::Rescan => crate::module::audit_rescan_arguments_hash()?,
        AuditAction::Prune => crate::module::audit_prune_arguments_hash(module_id)?,
        AuditAction::SecureRemove => crate::module_response::secure_remove_arguments_hash(
            module_id.expect("validated secure removal module id"),
        )?,
        AuditAction::RecoverSealed => {
            return crate::module_audit_log::manager_sealed_recovery_challenge(
                root,
                module_id.expect("validated sealed recovery module id"),
            );
        }
        AuditAction::CloseIncident => {
            return crate::module_audit_log::close_incident_challenge(
                root,
                module_id.expect("validated incident module id"),
                incident_id.expect("validated incident id"),
            );
        }
        AuditAction::DeleteQuarantinedScript => {
            crate::module_response::quarantined_script_delete_arguments_hash(
                incident_id.expect("validated quarantine entry id"),
            )?
        }
        AuditAction::RetryScriptContainment => {
            crate::module_response::quarantined_script_retry_arguments_hash(
                incident_id.expect("validated quarantine entry id"),
            )?
        }
    };
    crate::module_audit_log::manager_audit_auth_challenge(root, action, &arguments_hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_wire_names_round_trip_through_the_canonical_registry() {
        for descriptor in ACTION_DESCRIPTORS {
            assert_eq!(
                descriptor.wire_name.parse::<AuditAction>().unwrap(),
                descriptor.action
            );
            assert_eq!(descriptor.action.to_string(), descriptor.wire_name);
            assert_eq!(
                serde_json::to_string(&descriptor.action).unwrap(),
                format!("\"{}\"", descriptor.wire_name)
            );
        }
        assert_eq!(
            AuditAction::RecoverSealed
                .descriptor()
                .authorization_inventory,
            AuditAuthorizationInventory::ManagerSealedDamage
        );
        assert!(ACTION_DESCRIPTORS.iter().all(|descriptor| {
            descriptor.action == AuditAction::RecoverSealed
                || descriptor.authorization_inventory
                    == AuditAuthorizationInventory::CurrentCheckpoint
        }));
    }
}
