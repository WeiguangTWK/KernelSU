package me.weishu.kernelsu.ui.screen.securityaudit

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.basicMarquee
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.add
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.calculateEndPadding
import androidx.compose.foundation.layout.calculateStartPadding
import androidx.compose.foundation.layout.displayCutout
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.systemBars
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.outlined.Computer
import androidx.compose.material.icons.outlined.Language
import androidx.compose.material.icons.outlined.Schedule
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import me.weishu.kernelsu.R
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.Icon
import top.yukonga.miuix.kmp.basic.IconButton
import top.yukonga.miuix.kmp.basic.PullToRefresh
import top.yukonga.miuix.kmp.basic.Scaffold
import top.yukonga.miuix.kmp.basic.Text
import top.yukonga.miuix.kmp.basic.TopAppBar
import top.yukonga.miuix.kmp.basic.rememberPullToRefreshState
import top.yukonga.miuix.kmp.icon.MiuixIcons
import top.yukonga.miuix.kmp.icon.extended.Back
import top.yukonga.miuix.kmp.theme.MiuixTheme.colorScheme
import top.yukonga.miuix.kmp.utils.overScrollVertical
import top.yukonga.miuix.kmp.utils.scrollEndHaptic

@Composable
fun SecurityAuditScreenMiuix(
    state: SecurityAuditUiState,
    actions: SecurityAuditActions,
) {
    val pullState = rememberPullToRefreshState()
    var expandedModule by remember { mutableStateOf<String?>(null) }
    val refreshTexts = listOf(
        stringResource(R.string.refresh_pulling),
        stringResource(R.string.refresh_release),
        stringResource(R.string.refresh_refresh),
        stringResource(R.string.refresh_complete),
    )

    Scaffold(
        topBar = {
            TopAppBar(
                title = stringResource(R.string.security_audit_center),
                navigationIcon = {
                    IconButton(onClick = actions.onBack) {
                        val direction = LocalLayoutDirection.current
                        Icon(
                            modifier = Modifier.graphicsLayer {
                                if (direction == LayoutDirection.Rtl) scaleX = -1f
                            },
                            imageVector = MiuixIcons.Back,
                            contentDescription = null,
                            tint = colorScheme.onSurface,
                        )
                    }
                },
            )
        },
        contentWindowInsets = WindowInsets.systemBars.add(WindowInsets.displayCutout)
            .only(WindowInsetsSides.Horizontal),
    ) { innerPadding ->
        val direction = LocalLayoutDirection.current
        PullToRefresh(
            isRefreshing = state.isLoading || state.isRefreshing,
            pullToRefreshState = pullState,
            onRefresh = actions.onRefresh,
            refreshTexts = refreshTexts,
            contentPadding = PaddingValues(
                top = innerPadding.calculateTopPadding(),
                start = innerPadding.calculateStartPadding(direction),
                end = innerPadding.calculateEndPadding(direction),
            ),
        ) {
            LazyColumn(
                modifier = Modifier.fillMaxSize().scrollEndHaptic().overScrollVertical(),
                contentPadding = PaddingValues(top = innerPadding.calculateTopPadding() + 6.dp),
            ) {
                item { AuditOverviewMiuix(state) }
                if (state.interruptedInstalls > 0) {
                    item {
                        AuditMessageCardMiuix(
                            stringResource(R.string.security_audit_interrupted_count, state.interruptedInstalls),
                            alert = true,
                        )
                    }
                }
                state.errorMessage?.let { message ->
                    item { AuditMessageCardMiuix(message, alert = true) }
                }
                if (!state.isLoading && state.histories.isEmpty() && state.errorMessage == null) {
                    item { AuditEmptyMiuix() }
                }
                if (state.histories.isNotEmpty()) {
                    item {
                        Text(
                            text = stringResource(R.string.security_audit_modules),
                            modifier = Modifier.padding(horizontal = 24.dp, vertical = 8.dp),
                            fontSize = 14.sp,
                            fontWeight = FontWeight.SemiBold,
                            color = colorScheme.primary,
                        )
                    }
                    items(state.histories, key = { it.status.moduleId }) { history ->
                        AuditModuleCardMiuix(
                            history = history,
                            expanded = expandedModule == history.status.moduleId,
                            onClick = {
                                expandedModule = if (expandedModule == history.status.moduleId) null
                                else history.status.moduleId
                            },
                        )
                    }
                }
                item { Spacer(Modifier.height(WindowInsets.navigationBars.asPaddingValues().calculateBottomPadding())) }
            }
        }
    }
}

@Composable
private fun AuditOverviewMiuix(state: SecurityAuditUiState) {
    Column(
        modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text(
            stringResource(R.string.security_audit_overview),
            modifier = Modifier.padding(start = 12.dp, bottom = 2.dp),
            fontSize = 14.sp,
            fontWeight = FontWeight.SemiBold,
            color = colorScheme.primary,
        )
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            AuditMetricMiuix(state.highRiskModules, stringResource(R.string.security_audit_high_risk), Icons.Outlined.Security, state.highRiskModules > 0, Modifier.weight(1f))
            AuditMetricMiuix(state.networkModules, stringResource(R.string.security_audit_network), Icons.Outlined.Language, false, Modifier.weight(1f))
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            AuditMetricMiuix(state.binaryModules, stringResource(R.string.security_audit_binaries), Icons.Outlined.Computer, false, Modifier.weight(1f))
            AuditMetricMiuix(state.persistentScriptModules, stringResource(R.string.security_audit_persistent), Icons.Outlined.Schedule, false, Modifier.weight(1f))
        }
    }
}

@Composable
private fun AuditMetricMiuix(
    value: Int,
    label: String,
    icon: ImageVector,
    alert: Boolean,
    modifier: Modifier,
) {
    val tint = if (alert) colorScheme.error else colorScheme.primary
    Card(modifier = modifier, insideMargin = PaddingValues(16.dp)) {
        Column(verticalArrangement = Arrangement.spacedBy(5.dp)) {
            Icon(icon, contentDescription = null, tint = tint, modifier = Modifier.size(21.dp))
            Text(value.toString(), fontSize = 26.sp, fontWeight = FontWeight.Bold, color = tint)
            Text(label, fontSize = 12.sp, color = colorScheme.onSurfaceVariantSummary)
        }
    }
}

@Composable
private fun AuditModuleCardMiuix(
    history: AuditHistory,
    expanded: Boolean,
    onClick: () -> Unit,
) {
    val alert = history.isHighRisk() || history.hasInterruptedInstall()
    Card(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp).padding(bottom = 12.dp).animateContentSize(),
        insideMargin = PaddingValues(16.dp),
        showIndication = true,
        onClick = onClick,
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    imageVector = if (alert) Icons.Filled.Error else Icons.Outlined.Shield,
                    contentDescription = null,
                    tint = if (alert) colorScheme.error else colorScheme.primary,
                )
                Column(Modifier.padding(start = 12.dp).weight(1f)) {
                    Text(
                        history.displayName(),
                        modifier = Modifier.basicMarquee(),
                        fontSize = 17.sp,
                        fontWeight = FontWeight.SemiBold,
                        color = colorScheme.onSurface,
                        maxLines = 1,
                        softWrap = false,
                    )
                    Text(
                        history.packageFingerprint()?.let {
                            stringResource(R.string.security_audit_package_hash, it)
                        } ?: history.status.moduleId,
                        fontSize = 12.sp,
                        color = colorScheme.onSurfaceVariantSummary,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
            }
            Text(
                "${stringResource(R.string.security_audit_event_count, history.status.eventCount)} · ${formatAuditTime(history.latestTimestamp())}",
                fontSize = 12.sp,
                color = colorScheme.onSurfaceVariantSummary,
            )
            AnimatedVisibility(expanded) {
                AuditModuleDetailsMiuix(history)
            }
        }
    }
}

@Composable
private fun AuditModuleDetailsMiuix(history: AuditHistory) {
    Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text(
            stringResource(
                if (history.status.hmacVerified) R.string.security_audit_hmac_verified
                else R.string.security_audit_hmac_unverified
            ),
            fontSize = 13.sp,
            fontWeight = FontWeight.SemiBold,
            color = if (history.status.hmacVerified) colorScheme.primary else colorScheme.error,
        )
        Text(
            if (history.status.managerCheckpoint == "not_configured") {
                stringResource(R.string.security_audit_checkpoint_unavailable)
            } else {
                history.status.managerCheckpoint.replace('_', ' ')
            },
            fontSize = 12.sp,
            color = colorScheme.onSurfaceVariantSummary,
        )
        history.events.asReversed().forEach { event ->
            Column {
                Text(auditEventTitle(event), fontSize = 15.sp, fontWeight = FontWeight.SemiBold, color = colorScheme.onSurface)
                Text(
                    "#${event.sequence} · ${formatAuditTime(event.timestampUnixSeconds)}",
                    fontSize = 12.sp,
                    color = colorScheme.onSurfaceVariantSummary,
                )
                event.kind.error?.takeIf { it.isNotBlank() }?.let {
                    Text(it, fontSize = 12.sp, color = colorScheme.error)
                }
                event.kind.report?.findings?.take(4)?.forEach { finding ->
                    Text(
                        "[${finding.severity.uppercase()}] ${finding.title} · ${finding.path}${finding.line?.let { ":$it" }.orEmpty()}",
                        fontSize = 12.sp,
                        color = colorScheme.onSurfaceVariantSummary,
                    )
                }
                event.kind.reason?.let {
                    Text(it, fontSize = 12.sp, fontFamily = FontFamily.Monospace, color = colorScheme.error)
                }
            }
        }
    }
}

@Composable
private fun AuditMessageCardMiuix(message: String, alert: Boolean) {
    Card(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp).padding(bottom = 12.dp),
        insideMargin = PaddingValues(16.dp),
    ) {
        Text(message, color = if (alert) colorScheme.error else colorScheme.onSurface)
    }
}

@Composable
private fun AuditEmptyMiuix() {
    Column(
        modifier = Modifier.fillMaxWidth().padding(vertical = 52.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Icon(Icons.Outlined.Shield, contentDescription = null, modifier = Modifier.size(48.dp), tint = colorScheme.onSurfaceVariantSummary)
        Spacer(Modifier.height(12.dp))
        Text(stringResource(R.string.security_audit_empty), color = colorScheme.onSurfaceVariantSummary)
    }
}
