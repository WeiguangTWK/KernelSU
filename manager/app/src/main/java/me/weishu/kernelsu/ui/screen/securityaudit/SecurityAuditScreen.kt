package me.weishu.kernelsu.ui.screen.securityaudit

import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.compose.dropUnlessResumed
import androidx.lifecycle.viewmodel.compose.viewModel
import me.weishu.kernelsu.ui.LocalUiMode
import me.weishu.kernelsu.ui.UiMode
import me.weishu.kernelsu.ui.navigation3.LocalNavigator
import me.weishu.kernelsu.ui.viewmodel.SecurityAuditViewModel
import java.text.DateFormat
import java.util.Date

data class SecurityAuditActions(
    val onBack: () -> Unit,
    val onRefresh: () -> Unit,
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
    )
    when (LocalUiMode.current) {
        UiMode.Material -> SecurityAuditScreenMaterial(state, actions)
        UiMode.Miuix -> SecurityAuditScreenMiuix(state, actions)
    }
}

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
