use crate::{defs, ksucalls, metamodule, module, module_audit_log};
use anyhow::{Context, Result, ensure};
use log::{info, warn};
use std::collections::BTreeSet;
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

    let persistent_result = quarantine_persistent_scripts(audit_root);
    if let Err(error) = persistent_result {
        warn!("persistent startup script containment is incomplete: {error:#}");
    } else if boot_enforcement {
        for id in &ids {
            module_audit_log::set_containment_state(
                audit_root,
                id,
                module_audit_log::ContainmentState::Contained,
            )?;
        }
    }

    Ok(ids.into_iter().collect())
}

fn quarantine_persistent_scripts(audit_root: &Path) -> Result<()> {
    // Use only Manager-sealed evidence. Exact ownership is preferred. If a
    // damaged module has no surviving event, preserve paths attributed by every
    // other intact history and quarantine the remainder as uncertain ownership.
    let mut plans = module_audit_log::persistent_script_containment_plans(audit_root)?;
    plans.sort_by(|left, right| left.module_id.cmp(&right.module_id));
    for plan in plans.iter().filter(|plan| !plan.paths.is_empty()) {
        module_audit_log::quarantine_persistent_scripts(
            audit_root,
            &plan.module_id,
            &plan.paths,
            false,
        )?;
    }
    if let Some(owner) = plans.iter().find(|plan| plan.infer_unattributed) {
        let trusted = module_audit_log::trusted_persistent_script_paths(audit_root)?
            .into_iter()
            .collect::<BTreeSet<_>>();
        let unknown = collect_unattributed_persistent_scripts(PERSISTENT_SCRIPT_DIRS, &trusted)?;
        if !unknown.is_empty() {
            warn!(
                "audit history for {} has no trusted persistent-script inventory; quarantining {} unattributed startup scripts",
                owner.module_id,
                unknown.len()
            );
            module_audit_log::quarantine_persistent_scripts(
                audit_root,
                &owner.module_id,
                &unknown,
                true,
            )?;
        }
    }
    Ok(())
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
            if !entry.file_type()?.is_file() {
                continue;
            }
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
        ksucalls::check_kernel_safemode(),
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
        ksucalls::check_kernel_safemode(),
        "Manager-sealed audit recovery requires KernelSU safe mode"
    );
    module_audit_log::recover_manager_sealed_module(
        Path::new(defs::MODULE_AUDIT_DIR),
        module_id,
        authorization,
    )
}
