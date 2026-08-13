use crate::{defs, ksucalls, metamodule, module, module_audit_log};
use anyhow::{Context, Result, ensure};
use log::{info, warn};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const PERSISTENT_SCRIPT_DIRS: &[&str] = &[
    "/data/adb/service.d",
    "/data/adb/boot-completed.d",
    "/data/adb/bootcompleted.d",
];

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

pub fn requires_containment(id: &str) -> Result<bool> {
    module_audit_log::module_requires_containment(Path::new(defs::MODULE_AUDIT_DIR), id)
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
pub fn enforce_containment(boot_enforcement: bool) -> Result<Vec<String>> {
    let audit_root = Path::new(defs::MODULE_AUDIT_DIR);
    if !audit_root.exists() {
        return Ok(Vec::new());
    }

    let mut ids = BTreeSet::new();
    if let Ok(status) = module_audit_log::sealed_integrity_status(audit_root) {
        ids.extend(status.failures.into_iter().map(|failure| failure.module_id));
    }
    if let Ok(statuses) = module_audit_log::list_modules_resilient(audit_root, false) {
        ids.extend(
            statuses
                .into_iter()
                .filter(|status| status.unresolved_risk)
                .map(|status| status.module_id),
        );
    }

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

    Ok(ids.into_iter().collect())
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
