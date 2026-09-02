use crate::{
    module_audit_action::AuditAction,
    module_audit_log::{
        AuditIncidentState, AuditInventoryRelation, AuditRecoveryCondition,
        AuditRecoveryRequirementState, AuditRecoveryRoute, ContainmentState, VerifiedAuditSnapshot,
    },
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const AUDIT_ASSESSMENT_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AuditAssessmentContext {
    pub kernel_safe_mode: bool,
    pub module_content_ids: BTreeSet<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditModuleDisposition {
    Trusted,
    ContainmentRequired,
    SecureRemovalRequired,
    SealedRecoveryRequired,
}

impl AuditModuleDisposition {
    pub const fn requires_containment(self) -> bool {
        !matches!(self, Self::Trusted)
    }

    pub const fn requires_secure_removal(self) -> bool {
        matches!(
            self,
            Self::SecureRemovalRequired | Self::SealedRecoveryRequired
        )
    }

    pub const fn requires_sealed_recovery(self) -> bool {
        matches!(self, Self::SealedRecoveryRequired)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditModuleAssessment {
    pub module_id: String,
    pub disposition: AuditModuleDisposition,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub containment_state: Option<ContainmentState>,
    pub actions: Vec<AuditRecoveryRoute>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditAssessment {
    pub schema_version: u32,
    pub snapshot_revision: String,
    pub inventory_hash: String,
    pub inventory_relation: AuditInventoryRelation,
    pub kernel_safe_mode: bool,
    pub authorization_configured: bool,
    pub modules: Vec<AuditModuleAssessment>,
    pub stale_module_ids: Vec<String>,
    pub sealed_recovery_module_ids: Vec<String>,
    pub unaudited_module_ids: Vec<String>,
    pub unsealed_module_ids: Vec<String>,
}

impl AuditAssessment {
    pub fn module(&self, module_id: &str) -> Option<&AuditModuleAssessment> {
        self.modules
            .iter()
            .find(|assessment| assessment.module_id == module_id)
    }

    pub fn containment_module_ids(&self) -> BTreeSet<String> {
        self.modules
            .iter()
            .filter(|assessment| assessment.disposition.requires_containment())
            .map(|assessment| assessment.module_id.clone())
            .collect()
    }

    pub fn ensure_complete_inventory(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.unaudited_module_ids.is_empty(),
            "installed or pending modules have no verified audit history: {}",
            self.unaudited_module_ids.join(", ")
        );
        anyhow::ensure!(
            self.unsealed_module_ids.is_empty(),
            "module audit histories are not Manager-sealed: {}",
            self.unsealed_module_ids.join(", ")
        );
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct AssessedAuditSnapshot {
    pub snapshot: VerifiedAuditSnapshot,
    pub assessment: AuditAssessment,
}

pub fn assess_verified_snapshot(
    mut snapshot: VerifiedAuditSnapshot,
    context: &AuditAssessmentContext,
) -> AssessedAuditSnapshot {
    let sealed_failure_ids = snapshot
        .integrity_failures
        .iter()
        .map(|failure| failure.module_id.as_str())
        .collect::<BTreeSet<_>>();
    let authorization_configured = snapshot.authorization_status.configured;
    let mut modules = Vec::with_capacity(snapshot.histories.len());

    for history in &mut snapshot.histories {
        let module_id = history.status.module_id.clone();
        let content_present = context.module_content_ids.contains(&module_id);
        let sealed_failure = sealed_failure_ids.contains(module_id.as_str());
        let disposition = if sealed_failure {
            AuditModuleDisposition::SealedRecoveryRequired
        } else if history.status.unresolved_risk {
            AuditModuleDisposition::SecureRemovalRequired
        } else if history.status.containment_state.is_some() {
            AuditModuleDisposition::ContainmentRequired
        } else {
            AuditModuleDisposition::Trusted
        };

        let secure_removal = disposition.requires_secure_removal().then(|| {
            secure_removal_route(
                context.kernel_safe_mode,
                authorization_configured,
                content_present,
                sealed_failure,
            )
        });
        let sealed_recovery = sealed_failure
            .then(|| sealed_recovery_route(context.kernel_safe_mode, authorization_configured));

        for incident in &mut history.status.incidents {
            incident.recovery_routes = if sealed_failure {
                sealed_recovery.clone().into_iter().collect()
            } else {
                match incident.state {
                    AuditIncidentState::Detected => secure_removal.clone().into_iter().collect(),
                    AuditIncidentState::Resolved => {
                        vec![close_incident_route(authorization_configured)]
                    }
                    AuditIncidentState::Closed => Vec::new(),
                }
            };
        }

        let mut actions = Vec::new();
        if let Some(route) = sealed_recovery {
            actions.push(route);
        }
        if let Some(route) = secure_removal {
            actions.push(route);
        }
        modules.push(AuditModuleAssessment {
            module_id,
            disposition,
            containment_state: history.status.containment_state,
            actions,
        });
    }
    modules.sort_by(|left, right| left.module_id.cmp(&right.module_id));

    let audited_ids = modules
        .iter()
        .map(|assessment| assessment.module_id.as_str())
        .collect::<BTreeSet<_>>();
    let stale_module_ids = audited_ids
        .iter()
        .filter(|module_id| !context.module_content_ids.contains(**module_id))
        .map(|module_id| (*module_id).to_owned())
        .collect();
    let unaudited_module_ids = context
        .module_content_ids
        .iter()
        .filter(|module_id| !audited_ids.contains(module_id.as_str()))
        .cloned()
        .collect();
    let sealed_recovery_module_ids = modules
        .iter()
        .filter(|assessment| assessment.disposition.requires_sealed_recovery())
        .map(|assessment| assessment.module_id.clone())
        .collect();
    let unsealed_module_ids = snapshot
        .histories
        .iter()
        .filter(|history| {
            history.status.manager_checkpoint != crate::module_audit_log::CheckpointState::Sealed
        })
        .map(|history| history.status.module_id.clone())
        .collect();

    let assessment = AuditAssessment {
        schema_version: AUDIT_ASSESSMENT_SCHEMA_VERSION,
        snapshot_revision: snapshot.store_revision.clone(),
        inventory_hash: snapshot.checkpoint.inventory_hash.clone(),
        inventory_relation: snapshot.inventory_relation,
        kernel_safe_mode: context.kernel_safe_mode,
        authorization_configured,
        modules,
        stale_module_ids,
        sealed_recovery_module_ids,
        unaudited_module_ids,
        unsealed_module_ids,
    };
    AssessedAuditSnapshot {
        snapshot,
        assessment,
    }
}

pub fn recovery_route(
    action: AuditAction,
    destructive: bool,
    conditions: &[(&str, AuditRecoveryRequirementState)],
) -> AuditRecoveryRoute {
    AuditRecoveryRoute {
        action: action.route_name().to_owned(),
        available: !conditions
            .iter()
            .any(|(_, state)| *state == AuditRecoveryRequirementState::Unsatisfied),
        ready: conditions
            .iter()
            .all(|(_, state)| *state == AuditRecoveryRequirementState::Satisfied),
        destructive,
        conditions: conditions
            .iter()
            .map(|(kind, state)| AuditRecoveryCondition {
                kind: (*kind).to_owned(),
                state: *state,
            })
            .collect(),
    }
}

pub fn current_condition_state(satisfied: bool) -> AuditRecoveryRequirementState {
    if satisfied {
        AuditRecoveryRequirementState::Satisfied
    } else {
        AuditRecoveryRequirementState::Required
    }
}

pub fn structural_condition_state(satisfied: bool) -> AuditRecoveryRequirementState {
    if satisfied {
        AuditRecoveryRequirementState::Satisfied
    } else {
        AuditRecoveryRequirementState::Unsatisfied
    }
}

pub fn script_delete_route(
    audit_state_verified: bool,
    authorization_configured: bool,
    quarantine_regular_file: bool,
) -> AuditRecoveryRoute {
    recovery_route(
        AuditAction::DeleteQuarantinedScript,
        true,
        &[
            (
                "audit_state_verified",
                current_condition_state(audit_state_verified),
            ),
            (
                "manager_authorization",
                current_condition_state(authorization_configured),
            ),
            (
                "quarantine_regular_file",
                structural_condition_state(quarantine_regular_file),
            ),
        ],
    )
}

pub fn script_retry_route(
    audit_state_verified: bool,
    authorization_configured: bool,
    source_regular_file: bool,
) -> AuditRecoveryRoute {
    recovery_route(
        AuditAction::RetryScriptContainment,
        false,
        &[
            (
                "audit_state_verified",
                current_condition_state(audit_state_verified),
            ),
            (
                "manager_authorization",
                current_condition_state(authorization_configured),
            ),
            (
                "source_regular_file",
                structural_condition_state(source_regular_file),
            ),
        ],
    )
}

// Each flag maps directly to a separately named recovery requirement.
#[allow(clippy::fn_params_excessive_bools)]
fn secure_removal_route(
    kernel_safe_mode: bool,
    authorization_configured: bool,
    module_content_present: bool,
    sealed_history_recoverable: bool,
) -> AuditRecoveryRoute {
    let mut conditions = vec![
        (
            "audit_state_verified",
            AuditRecoveryRequirementState::Satisfied,
        ),
        (
            "kernel_safe_mode",
            current_condition_state(kernel_safe_mode),
        ),
        (
            "manager_authorization",
            current_condition_state(authorization_configured),
        ),
        (
            "module_content_present",
            structural_condition_state(module_content_present),
        ),
    ];
    if sealed_history_recoverable {
        conditions.push((
            "manager_sealed_history_recoverable",
            AuditRecoveryRequirementState::Satisfied,
        ));
    }
    recovery_route(AuditAction::SecureRemove, true, &conditions)
}

fn sealed_recovery_route(
    kernel_safe_mode: bool,
    authorization_configured: bool,
) -> AuditRecoveryRoute {
    recovery_route(
        AuditAction::RecoverSealed,
        false,
        &[
            (
                "audit_state_verified",
                AuditRecoveryRequirementState::Satisfied,
            ),
            (
                "kernel_safe_mode",
                current_condition_state(kernel_safe_mode),
            ),
            (
                "manager_seal_verified",
                AuditRecoveryRequirementState::Satisfied,
            ),
            (
                "manager_authorization",
                current_condition_state(authorization_configured),
            ),
        ],
    )
}

fn close_incident_route(authorization_configured: bool) -> AuditRecoveryRoute {
    recovery_route(
        AuditAction::CloseIncident,
        false,
        &[
            (
                "audit_state_verified",
                AuditRecoveryRequirementState::Satisfied,
            ),
            (
                "incident_resolved",
                AuditRecoveryRequirementState::Satisfied,
            ),
            (
                "manager_authorization",
                current_condition_state(authorization_configured),
            ),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_distinguishes_reachable_from_ready() {
        let route = recovery_route(
            AuditAction::SecureRemove,
            true,
            &[
                (
                    "module_content_present",
                    AuditRecoveryRequirementState::Satisfied,
                ),
                ("kernel_safe_mode", AuditRecoveryRequirementState::Required),
            ],
        );
        assert!(route.available);
        assert!(!route.ready);
    }

    #[test]
    fn structural_failure_makes_a_route_unavailable() {
        let route = recovery_route(
            AuditAction::SecureRemove,
            true,
            &[(
                "module_content_present",
                AuditRecoveryRequirementState::Unsatisfied,
            )],
        );
        assert!(!route.available);
        assert!(!route.ready);
    }
}
