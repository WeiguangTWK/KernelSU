package me.weishu.kernelsu.ui.screen.securityaudit

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.outlined.ChevronRight
import androidx.compose.material.icons.outlined.Computer
import androidx.compose.material.icons.outlined.Language
import androidx.compose.material.icons.outlined.Schedule
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.material3.pulltorefresh.PullToRefreshDefaults
import androidx.compose.material3.pulltorefresh.rememberPullToRefreshState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import me.weishu.kernelsu.R
import me.weishu.kernelsu.ui.component.material.ExpressiveScaffold
import me.weishu.kernelsu.ui.component.material.TonalCard
import me.weishu.kernelsu.ui.component.material.TopBarBackButton

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SecurityAuditScreenMaterial(
    state: SecurityAuditUiState,
    actions: SecurityAuditActions,
) {
    val pullState = rememberPullToRefreshState()
    var expandedModule by remember { mutableStateOf<String?>(null) }

    ExpressiveScaffold(
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.security_audit_center)) },
                navigationIcon = { TopBarBackButton(onClick = actions.onBack) },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = Color.Transparent),
            )
        },
        contentWindowInsets = WindowInsets.safeDrawing.only(WindowInsetsSides.Top + WindowInsetsSides.Horizontal),
    ) { innerPadding ->
        PullToRefreshBox(
            modifier = Modifier.fillMaxSize().padding(innerPadding),
            isRefreshing = state.isRefreshing,
            onRefresh = actions.onRefresh,
            state = pullState,
            indicator = {
                PullToRefreshDefaults.LoadingIndicator(
                    modifier = Modifier.align(Alignment.TopCenter),
                    isRefreshing = state.isRefreshing,
                    state = pullState,
                )
            },
        ) {
            when {
                state.isLoading -> Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator()
                }

                state.errorMessage != null && state.histories.isEmpty() -> AuditErrorMaterial(
                    message = state.errorMessage,
                    modifier = Modifier.align(Alignment.Center),
                )

                else -> LazyColumn(
                    modifier = Modifier.fillMaxSize(),
                    contentPadding = PaddingValues(start = 16.dp, end = 16.dp, bottom = 24.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    item { AuditOverviewMaterial(state) }
                    if (state.interruptedInstalls > 0) {
                        item {
                            AuditErrorMaterial(
                                stringResource(R.string.security_audit_interrupted_count, state.interruptedInstalls)
                            )
                        }
                    }
                    state.errorMessage?.let { message ->
                        item { AuditErrorMaterial(message) }
                    }
                    if (state.histories.isEmpty()) {
                        item { AuditEmptyMaterial() }
                    } else {
                        item {
                            Text(
                                text = stringResource(R.string.security_audit_modules),
                                style = MaterialTheme.typography.titleMedium,
                                modifier = Modifier.padding(top = 4.dp),
                            )
                        }
                        items(state.histories, key = { it.status.moduleId }) { history ->
                            AuditModuleCardMaterial(
                                history = history,
                                expanded = expandedModule == history.status.moduleId,
                                onClick = {
                                    expandedModule = if (expandedModule == history.status.moduleId) null
                                    else history.status.moduleId
                                },
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun AuditOverviewMaterial(state: SecurityAuditUiState) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(stringResource(R.string.security_audit_overview), style = MaterialTheme.typography.titleMedium)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            AuditMetricMaterial(
                value = state.highRiskModules,
                label = stringResource(R.string.security_audit_high_risk),
                icon = Icons.Outlined.Security,
                alert = state.highRiskModules > 0,
                modifier = Modifier.weight(1f),
            )
            AuditMetricMaterial(
                value = state.networkModules,
                label = stringResource(R.string.security_audit_network),
                icon = Icons.Outlined.Language,
                modifier = Modifier.weight(1f),
            )
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            AuditMetricMaterial(
                value = state.binaryModules,
                label = stringResource(R.string.security_audit_binaries),
                icon = Icons.Outlined.Computer,
                modifier = Modifier.weight(1f),
            )
            AuditMetricMaterial(
                value = state.persistentScriptModules,
                label = stringResource(R.string.security_audit_persistent),
                icon = Icons.Outlined.Schedule,
                modifier = Modifier.weight(1f),
            )
        }
    }
}

@Composable
private fun AuditMetricMaterial(
    value: Int,
    label: String,
    icon: ImageVector,
    modifier: Modifier = Modifier,
    alert: Boolean = false,
) {
    val tint = if (alert) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary
    TonalCard(modifier = modifier) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Icon(icon, contentDescription = null, tint = tint, modifier = Modifier.size(22.dp))
            Text(value.toString(), style = MaterialTheme.typography.headlineMedium, color = tint)
            Text(label, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun AuditModuleCardMaterial(
    history: AuditHistory,
    expanded: Boolean,
    onClick: () -> Unit,
) {
    val alert = history.isHighRisk() || history.hasInterruptedInstall()
    TonalCard(
        modifier = Modifier.fillMaxWidth().animateContentSize(),
        onClick = onClick,
        containerColor = if (alert) MaterialTheme.colorScheme.errorContainer else MaterialTheme.colorScheme.surfaceBright,
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = if (alert) Icons.Filled.Error else Icons.Outlined.Shield,
                    contentDescription = null,
                    tint = if (alert) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary,
                )
                Column(Modifier.padding(start = 12.dp).weight(1f)) {
                    Text(history.displayName(), style = MaterialTheme.typography.titleMedium, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    Text(
                        history.packageFingerprint()?.let {
                            stringResource(R.string.security_audit_package_hash, it)
                        } ?: history.status.moduleId,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
                Icon(Icons.Outlined.ChevronRight, contentDescription = null)
            }
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(
                    stringResource(R.string.security_audit_event_count, history.status.eventCount),
                    style = MaterialTheme.typography.labelMedium,
                )
                if (history.latestTimestamp() > 0) {
                    Text(
                        formatAuditTime(history.latestTimestamp()),
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            AnimatedVisibility(expanded) {
                AuditModuleDetailsMaterial(history)
            }
        }
    }
}

@Composable
private fun AuditModuleDetailsMaterial(history: AuditHistory) {
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text(
            stringResource(
                if (history.status.hmacVerified) R.string.security_audit_hmac_verified
                else R.string.security_audit_hmac_unverified
            ),
            style = MaterialTheme.typography.labelLarge,
            color = if (history.status.hmacVerified) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
        )
        Text(
            if (history.status.managerCheckpoint == "not_configured") {
                stringResource(R.string.security_audit_checkpoint_unavailable)
            } else {
                history.status.managerCheckpoint.replace('_', ' ')
            },
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        history.events.asReversed().forEach { event ->
            Column {
                Text(auditEventTitle(event), style = MaterialTheme.typography.titleSmall)
                Text(
                    "#${event.sequence} · ${formatAuditTime(event.timestampUnixSeconds)}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                event.kind.error?.takeIf { it.isNotBlank() }?.let {
                    Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                }
                val findings = event.kind.report?.findings.orEmpty()
                findings.take(4).forEach { finding ->
                    Text(
                        "[${finding.severity.uppercase()}] ${finding.title} · ${finding.path}${finding.line?.let { ":$it" }.orEmpty()}",
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                if (findings.size > 4) {
                    Text(
                        stringResource(R.string.security_audit_more_findings, findings.size - 4),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                event.kind.reason?.let {
                    Text(it, style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
                }
            }
        }
    }
}

@Composable
fun auditEventTitle(event: AuditEvent): String = when (event.kind.type) {
    "install_accepted" -> stringResource(R.string.security_audit_event_accepted)
    "install_result" -> if (event.kind.outcome == "installed") {
        stringResource(R.string.security_audit_event_installed)
    } else {
        stringResource(R.string.security_audit_event_failed)
    }
    "integrity_incident" -> stringResource(R.string.security_audit_event_integrity)
    else -> event.kind.type.replace('_', ' ')
}

@Composable
private fun AuditErrorMaterial(message: String, modifier: Modifier = Modifier) {
    TonalCard(modifier = modifier.fillMaxWidth(), containerColor = MaterialTheme.colorScheme.errorContainer) {
        Text(message, modifier = Modifier.padding(16.dp), color = MaterialTheme.colorScheme.onErrorContainer)
    }
}

@Composable
private fun AuditEmptyMaterial() {
    Column(
        modifier = Modifier.fillMaxWidth().padding(vertical = 48.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Icon(Icons.Outlined.Shield, contentDescription = null, modifier = Modifier.size(48.dp))
        Spacer(Modifier.height(12.dp))
        Text(stringResource(R.string.security_audit_empty), style = MaterialTheme.typography.bodyLarge)
    }
}
