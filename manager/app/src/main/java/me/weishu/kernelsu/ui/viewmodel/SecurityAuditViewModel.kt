package me.weishu.kernelsu.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import me.weishu.kernelsu.R
import me.weishu.kernelsu.ksuApp
import me.weishu.kernelsu.security.AuditCheckpointTrust
import me.weishu.kernelsu.security.AuditDashboardCache
import me.weishu.kernelsu.security.AuditModuleDisposition
import me.weishu.kernelsu.security.AuditPostCommitFailure
import me.weishu.kernelsu.security.AuditSnapshotPolicy
import me.weishu.kernelsu.security.ManagerAuditSnapshot
import me.weishu.kernelsu.security.SecureRemovalStage
import me.weishu.kernelsu.ui.screen.securityaudit.AuditHistory
import me.weishu.kernelsu.ui.screen.securityaudit.SecurityAuditUiState
import me.weishu.kernelsu.ui.screen.securityaudit.SecureRemovalPhase
import me.weishu.kernelsu.ui.screen.securityaudit.isHighRisk
import me.weishu.kernelsu.ui.screen.securityaudit.parseAuditHistories
import org.json.JSONArray
import org.json.JSONObject

class SecurityAuditViewModel : ViewModel() {
    private val _uiState = MutableStateFlow(SecurityAuditUiState())
    val uiState: StateFlow<SecurityAuditUiState> = _uiState.asStateFlow()
    private var refreshJob: Job? = null
    private val auditCoordinator get() = ksuApp.auditCoordinator

    init {
        viewModelScope.launch {
            auditCoordinator.progress.collect { progress ->
                if (progress == null) {
                    _uiState.update {
                        it.copy(isRefreshing = false, verificationModuleId = null)
                    }
                    return@collect
                }
                _uiState.update {
                    it.copy(
                        verificationModuleId = progress.moduleId,
                        verificationCompleted = progress.completed,
                        verificationTotal = progress.total,
                        isRefreshing = true,
                    )
                }
            }
        }
    }

    private fun sortedHistories(histories: Collection<AuditHistory>): List<AuditHistory> =
        histories.sortedWith(
            compareByDescending<AuditHistory> { it.isHighRisk() }
                .thenByDescending { history ->
                    history.events.maxOfOrNull { it.timestampUnixSeconds } ?: 0L
                }
        )

    private fun applyCachedDashboard(cache: AuditDashboardCache) {
        val payload = JSONObject(cache.payload)
        val histories = parseAuditHistories(payload.getJSONArray("histories").toString()).map {
            it.copy(
                status = it.status.copy(
                    managerCheckpoint = AuditCheckpointTrust.Verified.wireName
                )
            )
        }
        val stale = payload.optJSONArray("stale_module_ids") ?: JSONArray()
        _uiState.update { state ->
            if (state.histories.isNotEmpty()) state else state.copy(
                isLoading = false,
                isRefreshing = true,
                showingCachedSnapshot = true,
                histories = sortedHistories(histories),
                staleModuleIds = buildList {
                    for (index in 0 until stale.length()) add(stale.getString(index))
                },
                keyProtection = runCatching {
                    me.weishu.kernelsu.security.AuditKeyProtection.entries.first {
                        it.wireName == payload.optString("key_protection")
                    }
                }.getOrDefault(state.keyProtection),
            )
        }
    }

    fun refresh() = refresh(force = false)

    fun revalidate() = refresh(force = true)

    private fun refresh(force: Boolean) {
        refreshJob?.cancel()
        while (true) {
            val state = _uiState.value
            if (state.isRescanning || state.isPruning || state.secureRemovalInProgress) return
            if (
                _uiState.compareAndSet(
                    state,
                    state.copy(
                        isLoading = state.histories.isEmpty(),
                        isRefreshing = state.histories.isNotEmpty(),
                        errorMessage = null,
                    ),
                )
            ) break
        }
        refreshJob = viewModelScope.launch(Dispatchers.IO) {
            if (_uiState.value.histories.isEmpty()) {
                auditCoordinator.cachedDashboard()?.let(::applyCachedDashboard)
            }
            runCatching {
                auditCoordinator.snapshot(
                    if (force) AuditSnapshotPolicy.Revalidate
                    else AuditSnapshotPolicy.ReuseVerified
                )
            }.onSuccess(::applySnapshot)
                .onFailure { error ->
                    if (error is CancellationException) throw error
                    _uiState.update {
                        it.copy(
                            isLoading = false,
                            isRefreshing = false,
                            verificationModuleId = null,
                            errorMessage = error.message ?: error::class.java.simpleName,
                        )
                    }
                }
        }
    }

    private fun applySnapshot(result: ManagerAuditSnapshot) {
        val histories = sortedHistories(
            parseAuditHistories(result.rawHistories).map { history ->
                history.copy(
                    status = history.status.copy(
                        managerCheckpoint = result.checkpoint.trust.wireName
                    )
                )
            }
        )
        val current = _uiState.value
        _uiState.value = SecurityAuditUiState(
            isLoading = false,
            isRescanning = current.isRescanning,
            isPruning = current.isPruning,
            isRecovering = current.isRecovering,
            secureRemovalModuleId = current.secureRemovalModuleId,
            closingIncidentId = current.closingIncidentId,
            deletingScriptEntryId = current.deletingScriptEntryId,
            retryingScriptEntryId = current.retryingScriptEntryId,
            secureRemovalPhase = current.secureRemovalPhase,
            histories = histories,
            staleModuleIds = result.assessment?.staleModuleIds.orEmpty(),
            checkpointCompromised =
                result.checkpoint.trust == AuditCheckpointTrust.Compromised,
            checkpointIncident = result.checkpoint
                .takeIf { it.trust == AuditCheckpointTrust.Compromised }
                ?.detail,
            recoverableModuleIds = result.checkpoint.recoverableModules,
            sealedRecoveryModuleIds = result.assessment?.sealedRecoveryModuleIds.orEmpty(),
            recoverySafeMode = result.kernelSafeMode,
            auditInitialized = result.initialized,
            keyProtection = result.checkpoint.protection,
            auditAuthorizationReady = result.authorizationReady,
            assessment = result.assessment,
            emergencyStatus = result.emergencyStatus,
            errorMessage = result.synchronizationError?.let {
                it.message ?: it::class.java.simpleName
            },
        )
    }

    fun recoverCheckpointAfterChainRebuild() {
        while (true) {
            val state = _uiState.value
            if (
                state.isRecovering || state.isRescanning || state.isPruning ||
                !state.checkpointCompromised || state.recoverableModuleIds.isEmpty()
            ) return
            if (!state.recoverySafeMode) {
                _uiState.update {
                    it.copy(errorMessage = ksuApp.getString(R.string.security_audit_recovery_safe_mode))
                }
                return
            }
            if (_uiState.compareAndSet(state, state.copy(isRecovering = true, errorMessage = null))) {
                break
            }
        }
        viewModelScope.launch(Dispatchers.IO) {
            runCatching { auditCoordinator.recoverCheckpoint() }
                .onFailure(::showFailure)
            _uiState.update { it.copy(isRecovering = false) }
            refresh(force = false)
        }
    }

    fun rescanInstalledModules() {
        while (true) {
            val state = _uiState.value
            if (state.isRescanning || state.isPruning || state.auditMutationBlocked) return
            if (_uiState.compareAndSet(state, state.copy(isRescanning = true, errorMessage = null))) {
                break
            }
        }
        viewModelScope.launch(Dispatchers.IO) {
            runCatching { auditCoordinator.rescan() }
                .onFailure(::showFailure)
            _uiState.update { it.copy(isRescanning = false) }
            refresh(force = false)
        }
    }

    fun pruneStaleAuditHistories() {
        while (true) {
            val state = _uiState.value
            if (
                state.isPruning || state.isRescanning || state.auditMutationBlocked ||
                state.staleModuleIds.isEmpty()
            ) return
            if (_uiState.compareAndSet(state, state.copy(isPruning = true, errorMessage = null))) {
                break
            }
        }
        viewModelScope.launch(Dispatchers.IO) {
            runCatching { auditCoordinator.prune() }
                .onFailure(::showFailure)
            _uiState.update { it.copy(isPruning = false) }
            refresh(force = false)
        }
    }

    fun containForSecureRemoval(moduleId: String, onContained: () -> Unit) {
        val module = _uiState.value.assessment?.module(moduleId)
        if (
            module?.disposition !in setOf(
                AuditModuleDisposition.SecureRemovalRequired,
                AuditModuleDisposition.SealedRecoveryRequired,
            ) || module?.secureRemovalRoute?.available != true
        ) return
        viewModelScope.launch {
            runCatching {
                withContext(Dispatchers.IO) {
                    auditCoordinator.containForSecureRemoval(moduleId)
                }
            }
                .onSuccess { onContained() }
                .onFailure(::showFailure)
        }
    }

    fun securelyRemoveModule(moduleId: String) {
        while (true) {
            val state = _uiState.value
            if (!state.canSecurelyRemove(moduleId)) {
                _uiState.update {
                    it.copy(
                        errorMessage = ksuApp.getString(
                            R.string.security_audit_secure_remove_unavailable
                        )
                    )
                }
                return
            }
            val recovering = moduleId in state.assessment?.sealedRecoveryModuleIds.orEmpty()
            if (
                _uiState.compareAndSet(
                    state,
                    state.copy(
                        secureRemovalModuleId = moduleId,
                        secureRemovalPhase = if (recovering) {
                            SecureRemovalPhase.RecoveringAudit
                        } else {
                            SecureRemovalPhase.RemovingModule
                        },
                        errorMessage = null,
                    ),
                )
            ) break
        }
        viewModelScope.launch(Dispatchers.IO) {
            runCatching {
                auditCoordinator.securelyRemove(moduleId) { stage ->
                    _uiState.update { it.copy(secureRemovalPhase = stage.toUiPhase()) }
                }
            }.onSuccess {
                _uiState.update { it.copy(secureRemovalPhase = SecureRemovalPhase.Completed) }
            }.onFailure { error ->
                if (error is CancellationException) throw error
                val secureRemovalCommitted = (error as? AuditPostCommitFailure)
                    ?.receipts
                    ?.any { receipt ->
                        receipt.action == "secure-remove" && receipt.targets == listOf(moduleId)
                    } == true
                if (secureRemovalCommitted) {
                    _uiState.update {
                        it.copy(
                            secureRemovalPhase = SecureRemovalPhase.Completed,
                            errorMessage = error.message,
                        )
                    }
                } else {
                    _uiState.update {
                        it.copy(
                            secureRemovalModuleId = null,
                            secureRemovalPhase = null,
                            errorMessage = error.message ?: error::class.java.simpleName,
                        )
                    }
                }
            }
        }
    }

    fun closeIncident(moduleId: String, incidentId: String) {
        val incident = _uiState.value.histories
            .firstOrNull { it.status.moduleId == moduleId }
            ?.status
            ?.incidents
            ?.firstOrNull { it.incidentId == incidentId }
        if (
            incident?.state != "resolved" ||
            incident.recoveryRoutes.none { it.action == "close_incident" && it.ready } ||
            _uiState.value.auditMutationBlocked || _uiState.value.closingIncidentId != null
        ) return
        _uiState.update { it.copy(closingIncidentId = incidentId, errorMessage = null) }
        viewModelScope.launch(Dispatchers.IO) {
            runCatching { auditCoordinator.closeIncident(moduleId, incidentId) }
                .onFailure(::showFailure)
            _uiState.update { it.copy(closingIncidentId = null) }
            refresh(force = false)
        }
    }

    fun deleteQuarantinedScript(entryId: String) {
        val entry = _uiState.value.emergencyStatus
            ?.scriptQuarantines
            ?.asSequence()
            ?.flatMap { it.entries.asSequence() }
            ?.firstOrNull { it.entryId == entryId }
        if (
            entry?.recoveryRoutes?.none {
                it.action == "delete_quarantined_script" && it.ready
            } != false || _uiState.value.auditMutationBlocked ||
            _uiState.value.deletingScriptEntryId != null
        ) return
        _uiState.update { it.copy(deletingScriptEntryId = entryId, errorMessage = null) }
        viewModelScope.launch(Dispatchers.IO) {
            runCatching { auditCoordinator.deleteQuarantinedScript(entryId) }
                .onFailure(::showFailure)
            _uiState.update { it.copy(deletingScriptEntryId = null) }
            refresh(force = false)
        }
    }

    fun retryScriptContainment(entryId: String) {
        val entry = _uiState.value.emergencyStatus
            ?.scriptQuarantines
            ?.asSequence()
            ?.flatMap { it.entries.asSequence() }
            ?.firstOrNull { it.entryId == entryId }
        if (
            entry?.recoveryRoutes?.none {
                it.action == "retry_script_containment" && it.ready
            } != false || _uiState.value.auditMutationBlocked ||
            _uiState.value.retryingScriptEntryId != null
        ) return
        _uiState.update { it.copy(retryingScriptEntryId = entryId, errorMessage = null) }
        viewModelScope.launch(Dispatchers.IO) {
            runCatching { auditCoordinator.retryScriptContainment(entryId) }
                .onFailure(::showFailure)
            _uiState.update { it.copy(retryingScriptEntryId = null) }
            refresh(force = false)
        }
    }

    private fun showFailure(error: Throwable) {
        if (error is CancellationException) throw error
        _uiState.update {
            it.copy(errorMessage = error.message ?: error::class.java.simpleName)
        }
    }
}

private fun SecureRemovalStage.toUiPhase(): SecureRemovalPhase = when (this) {
    SecureRemovalStage.RecoveringAudit -> SecureRemovalPhase.RecoveringAudit
    SecureRemovalStage.AnchoringAudit -> SecureRemovalPhase.AnchoringAudit
    SecureRemovalStage.RemovingModule -> SecureRemovalPhase.RemovingModule
    SecureRemovalStage.RefreshingModules -> SecureRemovalPhase.RefreshingModules
}
