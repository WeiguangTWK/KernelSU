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
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.material3.pulltorefresh.PullToRefreshDefaults
import androidx.compose.material3.pulltorefresh.rememberPullToRefreshState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
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
import me.weishu.kernelsu.security.AuditKeyProtection
import me.weishu.kernelsu.ui.component.material.ExpressiveScaffold
import me.weishu.kernelsu.ui.component.material.TonalCard
import me.weishu.kernelsu.ui.component.material.TopBarBackButton

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SecurityAuditScreenMaterial(state: SecurityAuditUiState, actions: SecurityAuditActions) {
    AuditScaffoldMaterial(
        title = stringResource(R.string.security_audit_center),
        state = state,
        actions = actions,
        showRescan = true,
        showPrune = true,
    ) {
        if (state.isRefreshing) {
            item { AuditVerificationProgressMaterial(state) }
        }
        item { AuditOverviewMaterial(state, actions.onOpenCategory) }
        if (state.interruptedInstalls > 0) {
            item { AuditErrorMaterial(stringResource(R.string.security_audit_interrupted_count, state.interruptedInstalls)) }
        }
        state.checkpointIncident?.let {
            item {
                if (state.recoverableModuleIds.isNotEmpty()) {
                    AuditRecoveryMaterial(state, actions.onRecover)
                } else {
                    AuditErrorMaterial(stringResource(R.string.security_audit_checkpoint_incident, it))
                }
            }
        }
        state.errorMessage?.let { item { AuditErrorMaterial(it) } }
        state.secureRemovalPhase
            ?.takeUnless { it == SecureRemovalPhase.Completed }
            ?.let { phase -> item { AuditSecureRemovalProgressMaterial(phase) } }
        if (state.histories.isEmpty() && !state.isLoading) {
            item { AuditEmptyMaterial() }
        } else if (state.histories.isNotEmpty()) {
            item { SectionTitleMaterial(stringResource(R.string.security_audit_modules)) }
            items(state.histories, key = { it.status.moduleId }) { history ->
                AuditModuleCardMaterial(history) { actions.onOpenModule(history.status.moduleId) }
            }
        }
    }
}

@Composable
private fun AuditVerificationProgressMaterial(state: SecurityAuditUiState) {
    val label = state.verificationModuleId?.let { moduleId ->
        stringResource(
            R.string.security_audit_verifying_module,
            moduleId,
            state.verificationCompleted,
            state.verificationTotal,
        )
    } ?: if (state.showingCachedSnapshot) {
        stringResource(R.string.security_audit_snapshot_syncing)
    } else {
        stringResource(R.string.security_audit_finalizing_verification)
    }
    TonalCard(Modifier.fillMaxWidth()) {
        Row(
            Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            CircularProgressIndicator(Modifier.size(22.dp), strokeWidth = 2.dp)
            Text(
                label,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                style = MaterialTheme.typography.bodyMedium,
            )
        }
    }
}

@Composable
private fun AuditSecureRemovalProgressMaterial(phase: SecureRemovalPhase) {
    TonalCard(Modifier.fillMaxWidth()) {
        Row(
            Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            CircularProgressIndicator(Modifier.size(24.dp), strokeWidth = 2.dp)
            Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(
                    stringResource(secureRemovalPhaseLabel(phase)),
                    style = MaterialTheme.typography.titleSmall,
                )
                Text(
                    stringResource(R.string.security_audit_removal_wait),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}

private fun secureRemovalPhaseLabel(phase: SecureRemovalPhase): Int = when (phase) {
    SecureRemovalPhase.RecoveringAudit -> R.string.security_audit_removal_recovering
    SecureRemovalPhase.AnchoringAudit -> R.string.security_audit_removal_anchoring
    SecureRemovalPhase.RemovingModule -> R.string.security_audit_removal_removing
    SecureRemovalPhase.RefreshingModules,
    SecureRemovalPhase.Completed -> R.string.security_audit_removal_refreshing
}

@Composable
private fun AuditRecoveryMaterial(state: SecurityAuditUiState, onRecover: () -> Unit) {
    TonalCard(Modifier.fillMaxWidth(), containerColor = MaterialTheme.colorScheme.errorContainer) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text(
                stringResource(
                    R.string.security_audit_recovery_available,
                    state.recoverableModuleIds.joinToString(),
                ),
                color = MaterialTheme.colorScheme.onErrorContainer,
            )
            if (!state.recoverySafeMode) {
                Text(
                    stringResource(R.string.security_audit_recovery_safe_mode),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onErrorContainer,
                )
            }
            Button(
                onClick = onRecover,
                enabled = state.recoverySafeMode && !state.isRecovering,
            ) {
                if (state.isRecovering) {
                    CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                } else {
                    Text(stringResource(R.string.security_audit_recovery_action))
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SecurityAuditCategoryMaterial(
    category: AuditCategory,
    state: SecurityAuditUiState,
    actions: SecurityAuditActions,
) {
    val matches = state.histories.filter { it.hasCategory(category) }
    AuditScaffoldMaterial(
        title = auditCategoryLabel(category),
        state = state,
        actions = actions,
    ) {
        state.checkpointIncident?.let {
            item { AuditErrorMaterial(stringResource(R.string.security_audit_checkpoint_incident, it)) }
        }
        state.errorMessage?.let { item { AuditErrorMaterial(it) } }
        if (matches.isEmpty() && !state.isLoading) {
            item { AuditEmptyResultMaterial() }
        } else {
            item { SectionTitleMaterial(stringResource(R.string.security_audit_hit_modules, matches.size)) }
            items(matches, key = { it.status.moduleId }) { history ->
                AuditModuleLinkMaterial(history.status.moduleId) {
                    actions.onOpenModule(history.status.moduleId)
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SecurityAuditModuleMaterial(
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
    val messageCount = listOf(state.checkpointIncident, state.errorMessage).count { it != null }
    val targetItemIndex = when {
        focusIntegrity -> messageCount
        focusedGroupIndex >= 0 -> messageCount + 2 + focusedGroupIndex
        else -> -1
    }
    LaunchedEffect(targetItemIndex, state.isLoading) {
        if (!state.isLoading && targetItemIndex >= 0) {
            listState.animateScrollToItem(targetItemIndex)
        }
    }
    AuditScaffoldMaterial(
        title = history?.displayName() ?: moduleId,
        state = state,
        actions = actions,
        listState = listState,
    ) {
        state.checkpointIncident?.let {
            item { AuditErrorMaterial(stringResource(R.string.security_audit_checkpoint_incident, it)) }
        }
        state.errorMessage?.let { item { AuditErrorMaterial(it) } }
        state.secureRemovalPhase
            ?.takeUnless { it == SecureRemovalPhase.Completed }
            ?.let { phase -> item { AuditSecureRemovalProgressMaterial(phase) } }
        when {
            history == null && !state.isLoading -> item { AuditEmptyResultMaterial() }
            history != null -> {
                item { AuditIntegrityMaterial(history) }
                if (history.status.unresolvedRisk) {
                    item {
                        AuditErrorMaterial(stringResource(R.string.security_audit_isolation_reason))
                    }
                }
                if (
                    history.status.unresolvedRisk &&
                    history.integrityError == null &&
                    moduleId !in state.staleModuleIds
                ) {
                    item {
                        Button(
                            onClick = { actions.onRequestSecureRemoval(moduleId) },
                            enabled = state.secureRemovalModuleId == null && !state.isLoading,
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            if (state.secureRemovalModuleId == moduleId) {
                                CircularProgressIndicator(
                                    Modifier.size(18.dp),
                                    strokeWidth = 2.dp,
                                )
                            } else {
                                Icon(Icons.Outlined.Shield, contentDescription = null)
                                Spacer(Modifier.size(8.dp))
                                Text(stringResource(R.string.security_audit_secure_remove_action, moduleId))
                            }
                        }
                    }
                }
                if (groups.isEmpty()) {
                    item { AuditEmptyResultMaterial() }
                } else {
                    item { SectionTitleMaterial(stringResource(R.string.security_audit_findings)) }
                    items(groups, key = { it.category.key }) { group ->
                        AuditCategoryDetailsMaterial(
                            group = group,
                            initiallyExpanded = focusCategory == null || group.category == focusedFindingCategory,
                        )
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AuditScaffoldMaterial(
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
    ExpressiveScaffold(
        topBar = {
            TopAppBar(
                title = { Text(title, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                navigationIcon = { TopBarBackButton(onClick = actions.onBack) },
                actions = {
                    if (showPrune && state.staleModuleIds.isNotEmpty()) {
                        IconButton(
                            onClick = actions.onPrune,
                            enabled = !state.isPruning &&
                                !state.isRescanning &&
                                !state.auditMutationBlocked,
                        ) {
                            if (state.isPruning) {
                                CircularProgressIndicator(Modifier.size(22.dp), strokeWidth = 2.dp)
                            } else {
                                Icon(
                                    Icons.Outlined.DeleteSweep,
                                    contentDescription = stringResource(R.string.security_audit_prune),
                                )
                            }
                        }
                    }
                    if (showRescan) {
                        IconButton(
                            onClick = actions.onRescan,
                            enabled = !state.isRescanning &&
                                !state.isPruning &&
                                !state.auditMutationBlocked,
                        ) {
                            if (state.isRescanning) {
                                CircularProgressIndicator(Modifier.size(22.dp), strokeWidth = 2.dp)
                            } else {
                                Icon(
                                    Icons.Outlined.Refresh,
                                    contentDescription = stringResource(R.string.security_audit_rescan),
                                )
                            }
                        }
                    }
                },
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
            if (state.isLoading) {
                CircularProgressIndicator(Modifier.align(Alignment.Center))
            } else {
                LazyColumn(
                    modifier = Modifier.fillMaxSize(),
                    state = resolvedListState,
                    contentPadding = PaddingValues(start = 16.dp, end = 16.dp, bottom = 24.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                    content = content,
                )
            }
        }
    }
}

@Composable
private fun AuditOverviewMaterial(state: SecurityAuditUiState, onOpenCategory: (AuditCategory) -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        SectionTitleMaterial(stringResource(R.string.security_audit_overview))
        if (state.auditInitialized) {
            AuditKeyProtectionMaterial(state.keyProtection)
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            AuditMetricMaterial(state.highRiskModules, stringResource(R.string.security_audit_high_risk), Icons.Outlined.Security, Modifier.weight(1f), state.highRiskModules > 0) {
                onOpenCategory(AuditCategory.CriticalRisk)
            }
            AuditMetricMaterial(state.networkModules, stringResource(R.string.security_audit_network), Icons.Outlined.Language, Modifier.weight(1f)) {
                onOpenCategory(AuditCategory.Network)
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            AuditMetricMaterial(state.binaryModules, stringResource(R.string.security_audit_binaries), Icons.Outlined.Computer, Modifier.weight(1f)) {
                onOpenCategory(AuditCategory.PrebuiltBinaries)
            }
            AuditMetricMaterial(state.persistentScriptModules, stringResource(R.string.security_audit_persistent), Icons.Outlined.Schedule, Modifier.weight(1f)) {
                onOpenCategory(AuditCategory.PersistentScripts)
            }
        }
    }
}

@Composable
private fun AuditKeyProtectionMaterial(protection: AuditKeyProtection) {
    val title = auditKeyProtectionTitle(protection)
    val description = auditKeyProtectionDescription(protection)
    val alert = protection == AuditKeyProtection.Emergency ||
        protection == AuditKeyProtection.Unavailable
    val containerColor = when (protection) {
        AuditKeyProtection.Degraded -> MaterialTheme.colorScheme.tertiaryContainer
        AuditKeyProtection.Emergency,
        AuditKeyProtection.Unavailable -> MaterialTheme.colorScheme.errorContainer
        AuditKeyProtection.Hardware -> MaterialTheme.colorScheme.surfaceBright
    }
    val tint = when {
        alert -> MaterialTheme.colorScheme.error
        protection == AuditKeyProtection.Degraded -> MaterialTheme.colorScheme.tertiary
        else -> MaterialTheme.colorScheme.primary
    }
    TonalCard(Modifier.fillMaxWidth(), containerColor = containerColor) {
        Row(
            Modifier.padding(16.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(Icons.Outlined.Shield, null, tint = tint, modifier = Modifier.size(26.dp))
            Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
                Text(
                    stringResource(R.string.security_audit_key_protection),
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Text(title, style = MaterialTheme.typography.titleMedium, color = tint)
                Text(description, style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

@Composable
private fun AuditMetricMaterial(
    value: Int,
    label: String,
    icon: ImageVector,
    modifier: Modifier,
    alert: Boolean = false,
    onClick: () -> Unit,
) {
    val tint = if (alert) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary
    TonalCard(modifier = modifier, onClick = onClick) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Icon(icon, null, tint = tint, modifier = Modifier.size(22.dp))
            Text(value.toString(), style = MaterialTheme.typography.headlineMedium, color = tint)
            Text(label, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun AuditModuleCardMaterial(history: AuditHistory, onClick: () -> Unit) {
    val alert = history.isHighRisk()
    var expanded by remember(history.status.moduleId) { mutableStateOf(false) }
    TonalCard(
        modifier = Modifier.fillMaxWidth().animateContentSize(),
        onClick = { expanded = !expanded },
        containerColor = if (alert) MaterialTheme.colorScheme.errorContainer else MaterialTheme.colorScheme.surfaceBright,
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    if (alert) Icons.Filled.Error else Icons.Outlined.Shield,
                    null,
                    tint = if (alert) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary,
                )
                Text(
                    history.status.moduleId,
                    modifier = Modifier.padding(start = 12.dp).weight(1f),
                    style = MaterialTheme.typography.titleMedium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Icon(if (expanded) Icons.Outlined.ExpandLess else Icons.Outlined.ExpandMore, null)
            }
            AnimatedVisibility(expanded) {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    AuditCategorySummaryMaterial(history)
                    Text(
                        "${stringResource(R.string.security_audit_event_count, history.status.eventCount)} · ${formatAuditTime(history.latestTimestamp())}",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    IconButton(onClick = onClick, modifier = Modifier.align(Alignment.Start)) {
                        Icon(
                            Icons.Outlined.Info,
                            contentDescription = stringResource(R.string.security_audit_view_details),
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun AuditModuleLinkMaterial(moduleId: String, onClick: () -> Unit) {
    TonalCard(Modifier.fillMaxWidth(), onClick = onClick) {
        Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(
                moduleId,
                modifier = Modifier.weight(1f),
                style = MaterialTheme.typography.titleMedium,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Icon(Icons.Outlined.ChevronRight, null)
        }
    }
}

@Composable
private fun AuditCategorySummaryMaterial(history: AuditHistory) {
    history.integrityError?.let { error ->
        Text(
            error,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.error,
        )
        return
    }
    val groups = history.categoryGroups()
    if (groups.isEmpty()) {
        Text(
            stringResource(R.string.security_audit_no_findings),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    } else {
        groups.forEach { group ->
            Text(
                stringResource(R.string.security_audit_category_count, auditCategoryLabel(group.category), group.findings.size),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun AuditIntegrityMaterial(history: AuditHistory) {
    TonalCard(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(
                stringResource(if (history.status.hmacVerified) R.string.security_audit_hmac_verified else R.string.security_audit_hmac_unverified),
                style = MaterialTheme.typography.titleSmall,
                color = if (history.status.hmacVerified) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
            )
            Text(
                managerCheckpointLabel(history.status.managerCheckpoint),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            history.status.containmentState?.let { state ->
                Text(
                    stringResource(
                        when (state) {
                            "contained" -> R.string.security_audit_containment_active
                            "persistent_scripts_incomplete" ->
                                R.string.security_audit_containment_incomplete
                            else -> R.string.security_audit_containment_pending
                        }
                    ),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }
            if (history.status.quarantinedPersistentScripts > 0) {
                Text(
                    stringResource(
                        R.string.security_audit_persistent_quarantined,
                        history.status.quarantinedPersistentScripts,
                    ),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (history.status.persistentScriptOwnership == "uncertain") {
                Text(
                    stringResource(R.string.security_audit_persistent_uncertain),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }
            if (history.status.quarantinedPersistentScriptPaths.isNotEmpty()) {
                Text(
                    stringResource(R.string.security_audit_persistent_paths),
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                history.status.quarantinedPersistentScriptPaths.forEach { path ->
                    Text(
                        path,
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.primary,
                    )
                }
            }
            if (history.status.persistentScriptFailures.isNotEmpty()) {
                Text(
                    stringResource(R.string.security_audit_persistent_failures),
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.error,
                )
                history.status.persistentScriptFailures.forEach { failure ->
                    Text(
                        failure,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            }
            history.packageFingerprint()?.let {
                Text(stringResource(R.string.security_audit_package_hash, it), style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

@Composable
private fun AuditCategoryDetailsMaterial(
    group: AuditCategoryGroup,
    initiallyExpanded: Boolean,
) {
    var expanded by remember(group.category, initiallyExpanded) { mutableStateOf(initiallyExpanded) }
    TonalCard(Modifier.fillMaxWidth(), onClick = { expanded = !expanded }) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    stringResource(R.string.security_audit_category_count, auditCategoryLabel(group.category), group.findings.size),
                    modifier = Modifier.weight(1f),
                    style = MaterialTheme.typography.titleMedium,
                )
                Icon(if (expanded) Icons.Outlined.ExpandLess else Icons.Outlined.ExpandMore, null)
            }
            if (expanded) group.findings.forEach { AuditFindingMaterial(it) }
        }
    }
}

@Composable
private fun AuditFindingMaterial(finding: AuditFinding) {
    Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
        Text(finding.title, style = MaterialTheme.typography.titleSmall)
        Text(
            finding.path + finding.line?.let { ":$it" }.orEmpty(),
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
            color = MaterialTheme.colorScheme.primary,
        )
        if (finding.evidence.isNotBlank()) Text(finding.evidence, style = MaterialTheme.typography.bodySmall)
        if (finding.provenance.isNotEmpty()) {
            Text(finding.provenance.joinToString(" → "), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
fun auditEventTitle(event: AuditEvent): String = when (event.kind.type) {
    "install_accepted" -> stringResource(R.string.security_audit_event_accepted)
    "install_result" -> stringResource(if (event.kind.outcome == "installed") R.string.security_audit_event_installed else R.string.security_audit_event_failed)
    "installed_rescan" -> stringResource(R.string.security_audit_event_rescan)
    "installed_rescan_failed" -> stringResource(R.string.security_audit_event_rescan_failed)
    "integrity_incident" -> stringResource(R.string.security_audit_event_integrity)
    "secure_removal_completed" -> stringResource(R.string.security_audit_event_secure_removed)
    else -> event.kind.type.replace('_', ' ')
}

@Composable
private fun SectionTitleMaterial(title: String) {
    Text(title, style = MaterialTheme.typography.titleMedium, modifier = Modifier.padding(top = 4.dp))
}

@Composable
private fun AuditErrorMaterial(message: String) {
    TonalCard(Modifier.fillMaxWidth(), containerColor = MaterialTheme.colorScheme.errorContainer) {
        Text(message, Modifier.padding(16.dp), color = MaterialTheme.colorScheme.onErrorContainer)
    }
}

@Composable
private fun AuditEmptyMaterial() = AuditEmptyStateMaterial(stringResource(R.string.security_audit_empty))

@Composable
private fun AuditEmptyResultMaterial() = AuditEmptyStateMaterial(stringResource(R.string.security_audit_empty_result))

@Composable
private fun AuditEmptyStateMaterial(message: String) {
    Column(
        modifier = Modifier.fillMaxWidth().padding(vertical = 48.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Icon(Icons.Outlined.Shield, null, modifier = Modifier.size(48.dp))
        Spacer(Modifier.height(12.dp))
        Text(message, style = MaterialTheme.typography.bodyLarge)
    }
}
