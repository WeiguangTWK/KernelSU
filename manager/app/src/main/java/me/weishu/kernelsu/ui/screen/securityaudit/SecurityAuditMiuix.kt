package me.weishu.kernelsu.ui.screen.securityaudit

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.basicMarquee
import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.outlined.ChevronRight
import androidx.compose.material.icons.outlined.Computer
import androidx.compose.material.icons.outlined.DeleteSweep
import androidx.compose.material.icons.outlined.ExpandLess
import androidx.compose.material.icons.outlined.ExpandMore
import androidx.compose.material.icons.outlined.Info
import androidx.compose.material.icons.outlined.Language
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material.icons.outlined.Schedule
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
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
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import me.weishu.kernelsu.R
import top.yukonga.miuix.kmp.basic.Card
import top.yukonga.miuix.kmp.basic.CircularProgressIndicator
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
fun SecurityAuditScreenMiuix(state: SecurityAuditUiState, actions: SecurityAuditActions) {
    AuditScaffoldMiuix(
        title = stringResource(R.string.security_audit_center),
        state = state,
        actions = actions,
        showRescan = true,
        showPrune = true,
    ) {
        item { AuditOverviewMiuix(state, actions.onOpenCategory) }
        if (state.interruptedInstalls > 0) {
            item { AuditMessageCardMiuix(stringResource(R.string.security_audit_interrupted_count, state.interruptedInstalls), true) }
        }
        state.errorMessage?.let { item { AuditMessageCardMiuix(it, true) } }
        if (state.histories.isEmpty() && !state.isLoading) {
            item { AuditEmptyMiuix(stringResource(R.string.security_audit_empty)) }
        } else if (state.histories.isNotEmpty()) {
            item { SectionTitleMiuix(stringResource(R.string.security_audit_modules)) }
            items(state.histories, key = { it.status.moduleId }) { history ->
                AuditModuleCardMiuix(history) { actions.onOpenModule(history.status.moduleId) }
            }
        }
    }
}

@Composable
fun SecurityAuditCategoryMiuix(category: AuditCategory, state: SecurityAuditUiState, actions: SecurityAuditActions) {
    val matches = state.histories.filter { it.hasCategory(category) }
    AuditScaffoldMiuix(auditCategoryLabel(category), state, actions) {
        state.errorMessage?.let { item { AuditMessageCardMiuix(it, true) } }
        if (matches.isEmpty() && !state.isLoading) {
            item { AuditEmptyMiuix(stringResource(R.string.security_audit_empty_result)) }
        } else {
            item { SectionTitleMiuix(stringResource(R.string.security_audit_hit_modules, matches.size)) }
            items(matches, key = { it.status.moduleId }) { history ->
                AuditModuleLinkMiuix(history.status.moduleId) {
                    actions.onOpenModule(history.status.moduleId)
                }
            }
        }
    }
}

@Composable
fun SecurityAuditModuleMiuix(
    moduleId: String,
    focusCategory: AuditCategory?,
    state: SecurityAuditUiState,
    actions: SecurityAuditActions,
) {
    val history = state.histories.firstOrNull { it.status.moduleId == moduleId }
    val groups = history?.categoryGroups().orEmpty()
    val focusedFindingCategory = when (focusCategory) {
        AuditCategory.CriticalRisk -> groups.firstOrNull { group ->
            group.findings.any { it.severity == "critical" }
        }?.category
        else -> focusCategory
    }
    val listState = rememberLazyListState()
    val focusedGroupIndex = groups.indexOfFirst { it.category == focusedFindingCategory }
    val focusIntegrity = history != null && focusCategory == AuditCategory.CriticalRisk && focusedGroupIndex < 0
    val targetItemIndex = when {
        focusIntegrity -> if (state.errorMessage == null) 0 else 1
        focusedGroupIndex >= 0 -> (if (state.errorMessage == null) 2 else 3) + focusedGroupIndex
        else -> -1
    }
    LaunchedEffect(targetItemIndex, state.isLoading) {
        if (!state.isLoading && targetItemIndex >= 0) {
            listState.animateScrollToItem(targetItemIndex)
        }
    }
    AuditScaffoldMiuix(
        title = history?.displayName() ?: moduleId,
        state = state,
        actions = actions,
        listState = listState,
    ) {
        state.errorMessage?.let { item { AuditMessageCardMiuix(it, true) } }
        when {
            history == null && !state.isLoading -> item { AuditEmptyMiuix(stringResource(R.string.security_audit_empty_result)) }
            history != null -> {
                item { AuditIntegrityMiuix(history) }
                if (groups.isEmpty()) {
                    item { AuditEmptyMiuix(stringResource(R.string.security_audit_no_findings)) }
                } else {
                    item { SectionTitleMiuix(stringResource(R.string.security_audit_findings)) }
                    items(groups, key = { it.category.key }) { group ->
                        AuditCategoryDetailsMiuix(
                            group = group,
                            initiallyExpanded = focusCategory == null || group.category == focusedFindingCategory,
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun AuditScaffoldMiuix(
    title: String,
    state: SecurityAuditUiState,
    actions: SecurityAuditActions,
    showRescan: Boolean = false,
    showPrune: Boolean = false,
    listState: LazyListState? = null,
    content: androidx.compose.foundation.lazy.LazyListScope.() -> Unit,
) {
    val pullState = rememberPullToRefreshState()
    val resolvedListState = listState ?: rememberLazyListState()
    val refreshTexts = listOf(
        stringResource(R.string.refresh_pulling),
        stringResource(R.string.refresh_release),
        stringResource(R.string.refresh_refresh),
        stringResource(R.string.refresh_complete),
    )
    Scaffold(
        topBar = {
            TopAppBar(
                title = title,
                navigationIcon = { AuditBackButtonMiuix(actions.onBack) },
                actions = {
                    if (showPrune && state.staleModuleIds.isNotEmpty()) {
                        IconButton(
                            onClick = actions.onPrune,
                            enabled = !state.isPruning && !state.isRescanning,
                        ) {
                            if (state.isPruning) {
                                CircularProgressIndicator(Modifier.size(22.dp))
                            } else {
                                Icon(
                                    Icons.Outlined.DeleteSweep,
                                    stringResource(R.string.security_audit_prune),
                                )
                            }
                        }
                    }
                    if (showRescan) {
                        IconButton(
                            onClick = actions.onRescan,
                            enabled = !state.isRescanning && !state.isPruning,
                        ) {
                            if (state.isRescanning) {
                                CircularProgressIndicator(Modifier.size(22.dp))
                            } else {
                                Icon(Icons.Outlined.Refresh, stringResource(R.string.security_audit_rescan))
                            }
                        }
                    }
                },
            )
        },
        contentWindowInsets = WindowInsets.systemBars.add(WindowInsets.displayCutout).only(WindowInsetsSides.Horizontal),
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
                state = resolvedListState,
                contentPadding = PaddingValues(top = innerPadding.calculateTopPadding() + 6.dp),
                content = {
                    content()
                    item { Spacer(Modifier.height(WindowInsets.navigationBars.asPaddingValues().calculateBottomPadding())) }
                },
            )
        }
    }
}

@Composable
private fun AuditBackButtonMiuix(onClick: () -> Unit) {
    IconButton(onClick = onClick) {
        val direction = LocalLayoutDirection.current
        Icon(
            modifier = Modifier.graphicsLayer { if (direction == LayoutDirection.Rtl) scaleX = -1f },
            imageVector = MiuixIcons.Back,
            contentDescription = null,
            tint = colorScheme.onSurface,
        )
    }
}

@Composable
private fun AuditOverviewMiuix(state: SecurityAuditUiState, onOpenCategory: (AuditCategory) -> Unit) {
    Column(Modifier.padding(horizontal = 12.dp, vertical = 6.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        SectionTitleMiuix(stringResource(R.string.security_audit_overview), horizontalPadding = 12)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            AuditMetricMiuix(state.highRiskModules, stringResource(R.string.security_audit_high_risk), Icons.Outlined.Security, state.highRiskModules > 0, Modifier.weight(1f)) { onOpenCategory(AuditCategory.CriticalRisk) }
            AuditMetricMiuix(state.networkModules, stringResource(R.string.security_audit_network), Icons.Outlined.Language, false, Modifier.weight(1f)) { onOpenCategory(AuditCategory.Network) }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            AuditMetricMiuix(state.binaryModules, stringResource(R.string.security_audit_binaries), Icons.Outlined.Computer, false, Modifier.weight(1f)) { onOpenCategory(AuditCategory.PrebuiltBinaries) }
            AuditMetricMiuix(state.persistentScriptModules, stringResource(R.string.security_audit_persistent), Icons.Outlined.Schedule, false, Modifier.weight(1f)) { onOpenCategory(AuditCategory.PersistentScripts) }
        }
    }
}

@Composable
private fun AuditMetricMiuix(value: Int, label: String, icon: ImageVector, alert: Boolean, modifier: Modifier, onClick: () -> Unit) {
    val tint = if (alert) colorScheme.error else colorScheme.primary
    Card(modifier = modifier, insideMargin = PaddingValues(16.dp), showIndication = true, onClick = onClick) {
        Column(verticalArrangement = Arrangement.spacedBy(5.dp)) {
            Icon(icon, null, tint = tint, modifier = Modifier.size(21.dp))
            Text(value.toString(), fontSize = 26.sp, fontWeight = FontWeight.Bold, color = tint)
            Text(label, fontSize = 12.sp, color = colorScheme.onSurfaceVariantSummary)
        }
    }
}

@Composable
private fun AuditModuleCardMiuix(history: AuditHistory, onClick: () -> Unit) {
    val alert = history.isHighRisk()
    var expanded by remember(history.status.moduleId) { mutableStateOf(false) }
    Card(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp).padding(bottom = 12.dp).animateContentSize(),
        insideMargin = PaddingValues(16.dp),
        showIndication = true,
        onClick = { expanded = !expanded },
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(if (alert) Icons.Filled.Error else Icons.Outlined.Shield, null, tint = if (alert) colorScheme.error else colorScheme.primary)
                Text(
                    history.status.moduleId,
                    Modifier.padding(start = 12.dp).weight(1f).basicMarquee(),
                    fontSize = 17.sp,
                    fontWeight = FontWeight.SemiBold,
                    color = colorScheme.onSurface,
                    maxLines = 1,
                    softWrap = false,
                )
                Icon(
                    if (expanded) Icons.Outlined.ExpandLess else Icons.Outlined.ExpandMore,
                    null,
                    tint = colorScheme.onSurfaceVariantSummary,
                )
            }
            AnimatedVisibility(expanded) {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    AuditCategorySummaryMiuix(history)
                    Text(
                        "${stringResource(R.string.security_audit_event_count, history.status.eventCount)} · ${formatAuditTime(history.latestTimestamp())}",
                        fontSize = 12.sp,
                        color = colorScheme.onSurfaceVariantSummary,
                    )
                    IconButton(
                        modifier = Modifier.align(Alignment.Start),
                        onClick = onClick,
                    ) {
                        Icon(
                            Icons.Outlined.Info,
                            contentDescription = stringResource(R.string.security_audit_view_details),
                            tint = colorScheme.primary,
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun AuditModuleLinkMiuix(moduleId: String, onClick: () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp).padding(bottom = 12.dp),
        insideMargin = PaddingValues(16.dp),
        showIndication = true,
        onClick = onClick,
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                moduleId,
                modifier = Modifier.weight(1f).basicMarquee(),
                fontSize = 17.sp,
                fontWeight = FontWeight.SemiBold,
                maxLines = 1,
                softWrap = false,
            )
            Icon(Icons.Outlined.ChevronRight, null, tint = colorScheme.onSurfaceVariantSummary)
        }
    }
}

@Composable
private fun AuditCategorySummaryMiuix(history: AuditHistory) {
    val groups = history.categoryGroups()
    if (groups.isEmpty()) {
        Text(stringResource(R.string.security_audit_no_findings), fontSize = 13.sp, color = colorScheme.onSurfaceVariantSummary)
    } else {
        groups.forEach { group ->
            Text(
                stringResource(R.string.security_audit_category_count, auditCategoryLabel(group.category), group.findings.size),
                fontSize = 13.sp,
                color = colorScheme.onSurfaceVariantSummary,
            )
        }
    }
}

@Composable
private fun AuditIntegrityMiuix(history: AuditHistory) {
    Card(Modifier.fillMaxWidth().padding(horizontal = 12.dp).padding(bottom = 12.dp), insideMargin = PaddingValues(16.dp)) {
        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(
                stringResource(if (history.status.hmacVerified) R.string.security_audit_hmac_verified else R.string.security_audit_hmac_unverified),
                fontSize = 15.sp,
                fontWeight = FontWeight.SemiBold,
                color = if (history.status.hmacVerified) colorScheme.primary else colorScheme.error,
            )
            Text(
                if (history.status.managerCheckpoint == "not_configured") stringResource(R.string.security_audit_checkpoint_unavailable)
                else history.status.managerCheckpoint.replace('_', ' '),
                fontSize = 12.sp,
                color = colorScheme.onSurfaceVariantSummary,
            )
            history.packageFingerprint()?.let { Text(stringResource(R.string.security_audit_package_hash, it), fontSize = 12.sp) }
        }
    }
}

@Composable
private fun AuditCategoryDetailsMiuix(
    group: AuditCategoryGroup,
    initiallyExpanded: Boolean,
) {
    var expanded by remember(group.category, initiallyExpanded) { mutableStateOf(initiallyExpanded) }
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp)
            .padding(bottom = 12.dp),
        insideMargin = PaddingValues(16.dp),
        showIndication = true,
        onClick = { expanded = !expanded },
    ) {
        Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    stringResource(R.string.security_audit_category_count, auditCategoryLabel(group.category), group.findings.size),
                    modifier = Modifier.weight(1f),
                    fontSize = 17.sp,
                    fontWeight = FontWeight.SemiBold,
                )
                Icon(if (expanded) Icons.Outlined.ExpandLess else Icons.Outlined.ExpandMore, null)
            }
            if (expanded) group.findings.forEach { AuditFindingMiuix(it) }
        }
    }
}

@Composable
private fun AuditFindingMiuix(finding: AuditFinding) {
    Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
        Text(finding.title, fontSize = 15.sp, fontWeight = FontWeight.SemiBold)
        Text(
            finding.path + finding.line?.let { ":$it" }.orEmpty(),
            fontSize = 12.sp,
            fontFamily = FontFamily.Monospace,
            color = colorScheme.primary,
        )
        if (finding.evidence.isNotBlank()) Text(finding.evidence, fontSize = 13.sp, color = colorScheme.onSurfaceVariantSummary)
        if (finding.provenance.isNotEmpty()) Text(finding.provenance.joinToString(" → "), fontSize = 11.sp, color = colorScheme.onSurfaceVariantSummary)
    }
}

@Composable
private fun SectionTitleMiuix(title: String, horizontalPadding: Int = 24) {
    Text(
        title,
        modifier = Modifier.padding(horizontal = horizontalPadding.dp, vertical = 8.dp),
        fontSize = 14.sp,
        fontWeight = FontWeight.SemiBold,
        color = colorScheme.primary,
    )
}

@Composable
private fun AuditMessageCardMiuix(message: String, alert: Boolean) {
    Card(Modifier.fillMaxWidth().padding(horizontal = 12.dp).padding(bottom = 12.dp), insideMargin = PaddingValues(16.dp)) {
        Text(message, color = if (alert) colorScheme.error else colorScheme.onSurface)
    }
}

@Composable
private fun AuditEmptyMiuix(message: String) {
    Column(Modifier.fillMaxWidth().padding(vertical = 52.dp), horizontalAlignment = Alignment.CenterHorizontally) {
        Icon(Icons.Outlined.Shield, null, modifier = Modifier.size(48.dp), tint = colorScheme.onSurfaceVariantSummary)
        Spacer(Modifier.height(12.dp))
        Text(message, color = colorScheme.onSurfaceVariantSummary)
    }
}
