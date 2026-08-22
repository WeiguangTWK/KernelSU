package me.weishu.kernelsu.ui.screen.securityaudit

import androidx.activity.compose.BackHandler
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.compose.dropUnlessResumed
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.compose.ui.res.stringResource
import me.weishu.kernelsu.R
import me.weishu.kernelsu.ksuApp
import me.weishu.kernelsu.security.AuditKeyProtection
import me.weishu.kernelsu.ui.LocalUiMode
import me.weishu.kernelsu.ui.UiMode
import me.weishu.kernelsu.ui.component.dialog.rememberConfirmDialog
import me.weishu.kernelsu.ui.component.rebootlistpopup.rememberRebootAction
import me.weishu.kernelsu.ui.navigation3.LocalNavigator
import me.weishu.kernelsu.ui.navigation3.Route
import me.weishu.kernelsu.ui.viewmodel.SecurityAuditViewModel
import java.text.DateFormat
import java.util.Date

data class SecurityAuditActions(
    val onBack: () -> Unit,
    val onRefresh: () -> Unit,
    val onRescan: () -> Unit,
    val onPrune: () -> Unit,
    val onRecover: () -> Unit,
    val onRequestSecureRemoval: (String) -> Unit,
    val onCloseIncident: (String, String) -> Unit,
    val onDeleteQuarantinedScript: (String) -> Unit,
    val onRetryScriptContainment: (String) -> Unit,
    val onOpenCategory: (AuditCategory) -> Unit,
    val onOpenModule: (String) -> Unit,
)

@Composable
fun SecurityAuditScreen() {
    val navigator = LocalNavigator.current
    val viewModel = viewModel<SecurityAuditViewModel>()
    val state by viewModel.uiState.collectAsStateWithLifecycle()

    LaunchedEffect(Unit) {
        viewModel.refresh()
    }

    val pruneDialog = rememberConfirmDialog(onConfirm = viewModel::pruneStaleAuditHistories)
    val pruneTitle = stringResource(R.string.security_audit_prune_title)
    val pruneMessage = stringResource(
        R.string.security_audit_prune_message,
        state.staleModuleIds.size,
        state.staleModuleIds.joinToString("\n") { "• $it" },
    )
    val pruneConfirm = stringResource(R.string.security_audit_prune_confirm)
    val recoveryDialog = rememberConfirmDialog(
        onConfirm = viewModel::recoverCheckpointAfterChainRebuild
    )
    val recoveryTitle = stringResource(R.string.security_audit_recovery_title)
    val recoveryMessage = stringResource(
        R.string.security_audit_recovery_message,
        state.recoverableModuleIds.joinToString("\n") { "• $it" },
    )
    val recoveryConfirm = stringResource(R.string.security_audit_recovery_confirm)
    var pendingScriptDeletion by remember { mutableStateOf<String?>(null) }
    val scriptDeleteDialog = rememberConfirmDialog(
        onConfirm = {
            pendingScriptDeletion?.let(viewModel::deleteQuarantinedScript)
            pendingScriptDeletion = null
        }
    )
    val scriptDeleteTitle = stringResource(R.string.security_audit_script_delete_title)
    val scriptDeleteConfirm = stringResource(R.string.security_audit_script_delete_confirm)

    val actions = SecurityAuditActions(
        onBack = dropUnlessResumed { navigator.pop() },
        onRefresh = viewModel::refresh,
        onRescan = viewModel::rescanInstalledModules,
        onPrune = {
            pruneDialog.showConfirm(
                title = pruneTitle,
                content = pruneMessage,
                confirm = pruneConfirm,
            )
        },
        onRecover = {
            recoveryDialog.showConfirm(
                title = recoveryTitle,
                content = recoveryMessage,
                confirm = recoveryConfirm,
            )
        },
        onRequestSecureRemoval = {},
        onCloseIncident = viewModel::closeIncident,
        onDeleteQuarantinedScript = { entryId ->
            val entry = state.emergencyStatus
                ?.scriptQuarantines
                ?.asSequence()
                ?.flatMap { it.entries.asSequence() }
                ?.firstOrNull { it.entryId == entryId }
            if (entry != null) {
                pendingScriptDeletion = entryId
                scriptDeleteDialog.showConfirm(
                    title = scriptDeleteTitle,
                    content = ksuApp.getString(
                        R.string.security_audit_script_delete_message,
                        entry.quarantinePath,
                    ),
                    confirm = scriptDeleteConfirm,
                )
            }
        },
        onRetryScriptContainment = viewModel::retryScriptContainment,
        onOpenCategory = { navigator.push(Route.SecurityAuditCategory(it.key)) },
        onOpenModule = { navigator.push(Route.SecurityAuditModule(it)) },
    )
    when (LocalUiMode.current) {
        UiMode.Material -> SecurityAuditScreenMaterial(state, actions)
        UiMode.Miuix -> SecurityAuditScreenMiuix(state, actions)
    }
}

@Composable
fun SecurityAuditCategoryScreen(categoryKey: String) {
    val navigator = LocalNavigator.current
    val viewModel = viewModel<SecurityAuditViewModel>()
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val category = AuditCategory.fromKey(categoryKey)
    LaunchedEffect(Unit) { viewModel.refresh() }
    val actions = SecurityAuditActions(
        onBack = dropUnlessResumed { navigator.pop() },
        onRefresh = viewModel::refresh,
        onRescan = viewModel::rescanInstalledModules,
        onPrune = {},
        onRecover = viewModel::recoverCheckpointAfterChainRebuild,
        onRequestSecureRemoval = {},
        onCloseIncident = viewModel::closeIncident,
        onDeleteQuarantinedScript = viewModel::deleteQuarantinedScript,
        onRetryScriptContainment = viewModel::retryScriptContainment,
        onOpenCategory = {},
        onOpenModule = { navigator.push(Route.SecurityAuditModule(it, category.key)) },
    )
    when (LocalUiMode.current) {
        UiMode.Material -> SecurityAuditCategoryMaterial(category, state, actions)
        UiMode.Miuix -> SecurityAuditCategoryMiuix(category, state, actions)
    }
}

@Composable
fun SecurityAuditModuleScreen(
    moduleId: String,
    focusCategoryKey: String? = null,
    requestSecureRemoval: Boolean = false,
) {
    val navigator = LocalNavigator.current
    val viewModel = viewModel<SecurityAuditViewModel>()
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val focusCategory = focusCategoryKey?.let { AuditCategory.fromKey(it) }
    val reboot = rememberRebootAction()
    LaunchedEffect(Unit) { viewModel.refresh() }
    val secureRemovalDialog = rememberConfirmDialog(
        onConfirm = {
            if (state.recoverySafeMode) {
                viewModel.securelyRemoveModule(moduleId)
            } else {
                viewModel.containForSecureRemoval(moduleId) { reboot("") }
            }
        }
    )
    val secureRemovalTitle = stringResource(R.string.security_audit_secure_remove_title, moduleId)
    val secureRemovalMessage = stringResource(
        if (state.recoverySafeMode) {
            R.string.security_audit_secure_remove_message
        } else {
            R.string.security_audit_secure_remove_reboot_guide
        },
        moduleId,
    )
    val secureRemovalConfirm = stringResource(
        if (state.recoverySafeMode) {
            R.string.security_audit_secure_remove_confirm
        } else {
            R.string.security_audit_secure_remove_reboot
        }
    )
    var removalPromptShown by remember(moduleId, requestSecureRemoval) { mutableStateOf(false) }
    val secureRemovalAvailable = state.canSecurelyRemove(moduleId)
    LaunchedEffect(requestSecureRemoval, secureRemovalAvailable) {
        if (
            requestSecureRemoval && !removalPromptShown &&
            secureRemovalAvailable
        ) {
            removalPromptShown = true
            secureRemovalDialog.showConfirm(
                title = secureRemovalTitle,
                content = secureRemovalMessage,
                confirm = secureRemovalConfirm,
            )
        }
    }
    BackHandler(enabled = state.secureRemovalInProgress) {}
    LaunchedEffect(state.secureRemovalPhase) {
        if (state.secureRemovalPhase == SecureRemovalPhase.Completed) {
            navigator.pop()
        }
    }
    val actions = SecurityAuditActions(
        onBack = dropUnlessResumed {
            if (!state.secureRemovalInProgress) navigator.pop()
        },
        onRefresh = viewModel::refresh,
        onRescan = viewModel::rescanInstalledModules,
        onPrune = {},
        onRecover = viewModel::recoverCheckpointAfterChainRebuild,
        onRequestSecureRemoval = {
            secureRemovalDialog.showConfirm(
                title = secureRemovalTitle,
                content = secureRemovalMessage,
                confirm = secureRemovalConfirm,
            )
        },
        onCloseIncident = viewModel::closeIncident,
        onDeleteQuarantinedScript = viewModel::deleteQuarantinedScript,
        onRetryScriptContainment = viewModel::retryScriptContainment,
        onOpenCategory = {},
        onOpenModule = {},
    )
    when (LocalUiMode.current) {
        UiMode.Material -> SecurityAuditModuleMaterial(moduleId, focusCategory, state, actions)
        UiMode.Miuix -> SecurityAuditModuleMiuix(moduleId, focusCategory, state, actions)
    }
}

@Composable
fun auditCategoryLabel(category: AuditCategory): String = stringResource(
    when (category) {
        AuditCategory.CriticalRisk -> R.string.security_audit_category_critical
        AuditCategory.PersistentScripts -> R.string.security_audit_category_persistent
        AuditCategory.ExternalFilesystem -> R.string.security_audit_category_external_fs
        AuditCategory.PartitionWrites -> R.string.security_audit_category_partition
        AuditCategory.DestructiveDeletes -> R.string.security_audit_category_delete
        AuditCategory.Network -> R.string.security_audit_category_network
        AuditCategory.PrebuiltBinaries -> R.string.security_audit_category_binary
        AuditCategory.PackedContent -> R.string.security_audit_category_packed
        AuditCategory.ModuleScripts -> R.string.security_audit_category_scripts
        AuditCategory.ArchiveSafety -> R.string.security_audit_category_archive
        AuditCategory.ModuleCleanup -> R.string.security_audit_category_cleanup
        AuditCategory.Other -> R.string.security_audit_category_other
    }
)

@Composable
fun managerCheckpointLabel(state: String): String = when (state) {
    "keystore_initialized" -> stringResource(R.string.security_audit_checkpoint_initialized)
    "keystore_verified" -> stringResource(R.string.security_audit_checkpoint_verified)
    "keystore_compromised" -> stringResource(R.string.security_audit_checkpoint_compromised)
    else -> stringResource(R.string.security_audit_checkpoint_unavailable)
}

@Composable
fun auditKeyProtectionTitle(protection: AuditKeyProtection): String = stringResource(
    when (protection) {
        AuditKeyProtection.Hardware -> R.string.security_audit_key_hardware
        AuditKeyProtection.Degraded -> R.string.security_audit_key_degraded
        AuditKeyProtection.Emergency -> R.string.security_audit_key_emergency
        AuditKeyProtection.Unavailable -> R.string.security_audit_key_unavailable
    }
)

@Composable
fun auditKeyProtectionDescription(protection: AuditKeyProtection): String = stringResource(
    when (protection) {
        AuditKeyProtection.Hardware -> R.string.security_audit_key_hardware_desc
        AuditKeyProtection.Degraded -> R.string.security_audit_key_degraded_desc
        AuditKeyProtection.Emergency -> R.string.security_audit_key_emergency_desc
        AuditKeyProtection.Unavailable -> R.string.security_audit_key_unavailable_desc
    }
)

fun formatAuditTime(timestampUnixSeconds: Long): String = DateFormat
    .getDateTimeInstance(DateFormat.SHORT, DateFormat.MEDIUM)
    .format(Date(timestampUnixSeconds * 1_000L))

fun AuditHistory.latestTimestamp(): Long = events.maxOfOrNull { it.timestampUnixSeconds } ?: 0L

fun AuditHistory.latestFindings(): List<AuditFinding> = latestReport()?.findings.orEmpty()

fun AuditHistory.hasInterruptedInstall(): Boolean {
    val accepted = events.filter { it.kind.type == "install_accepted" }.mapNotNull { it.kind.attemptId }.toSet()
    val completed = events.filter { it.kind.type == "install_result" }.mapNotNull { it.kind.attemptId }.toSet()
    return (accepted - completed).isNotEmpty()
}
