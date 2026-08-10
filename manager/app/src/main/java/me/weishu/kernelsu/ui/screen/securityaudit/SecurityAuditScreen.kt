package me.weishu.kernelsu.ui.screen.securityaudit

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.compose.dropUnlessResumed
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.compose.ui.res.stringResource
import me.weishu.kernelsu.R
import me.weishu.kernelsu.ui.LocalUiMode
import me.weishu.kernelsu.ui.UiMode
import me.weishu.kernelsu.ui.navigation3.LocalNavigator
import me.weishu.kernelsu.ui.navigation3.Route
import me.weishu.kernelsu.ui.viewmodel.SecurityAuditViewModel
import java.text.DateFormat
import java.util.Date

data class SecurityAuditActions(
    val onBack: () -> Unit,
    val onRefresh: () -> Unit,
    val onRescan: () -> Unit,
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

    val actions = SecurityAuditActions(
        onBack = dropUnlessResumed { navigator.pop() },
        onRefresh = viewModel::refresh,
        onRescan = viewModel::rescanInstalledModules,
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
        onOpenCategory = {},
        onOpenModule = { navigator.push(Route.SecurityAuditModule(it, category.key)) },
    )
    when (LocalUiMode.current) {
        UiMode.Material -> SecurityAuditCategoryMaterial(category, state, actions)
        UiMode.Miuix -> SecurityAuditCategoryMiuix(category, state, actions)
    }
}

@Composable
fun SecurityAuditModuleScreen(moduleId: String, focusCategoryKey: String? = null) {
    val navigator = LocalNavigator.current
    val viewModel = viewModel<SecurityAuditViewModel>()
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val focusCategory = focusCategoryKey?.let { AuditCategory.fromKey(it) }
    LaunchedEffect(Unit) { viewModel.refresh() }
    val actions = SecurityAuditActions(
        onBack = dropUnlessResumed { navigator.pop() },
        onRefresh = viewModel::refresh,
        onRescan = viewModel::rescanInstalledModules,
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
