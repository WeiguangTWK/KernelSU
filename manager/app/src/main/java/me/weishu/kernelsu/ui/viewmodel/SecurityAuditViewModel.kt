package me.weishu.kernelsu.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import me.weishu.kernelsu.Natives
import me.weishu.kernelsu.R
import me.weishu.kernelsu.ksuApp
import me.weishu.kernelsu.security.AuditCheckpointTrust
import me.weishu.kernelsu.security.AuditCheckpointVerification
import me.weishu.kernelsu.security.ModuleAuditCheckpointStore
import me.weishu.kernelsu.security.requiresAuditSealCommit
import me.weishu.kernelsu.ui.screen.securityaudit.AuditHistory
import me.weishu.kernelsu.ui.screen.securityaudit.SecurityAuditUiState
import me.weishu.kernelsu.ui.screen.securityaudit.isHighRisk
import me.weishu.kernelsu.ui.screen.securityaudit.parseAuditHistories
import me.weishu.kernelsu.ui.screen.securityaudit.parseStaleAuditModuleIds
import me.weishu.kernelsu.ui.util.commitModuleAuditSeal
import me.weishu.kernelsu.ui.util.containModuleForSecureRemoval
import me.weishu.kernelsu.ui.util.getModuleAuditHistories
import me.weishu.kernelsu.ui.util.getModuleAuditCheckpoint
import me.weishu.kernelsu.ui.util.getModuleAuditAuthorizationChallenge
import me.weishu.kernelsu.ui.util.getModuleAuditAuthorizationStatus
import me.weishu.kernelsu.ui.util.getModuleAuditSealStatus
import me.weishu.kernelsu.ui.util.getStaleModuleAuditHistories
import me.weishu.kernelsu.ui.util.pruneStaleModuleAuditHistories
import me.weishu.kernelsu.ui.util.registerModuleAuditAuthorizationKey
import me.weishu.kernelsu.ui.util.rescanInstalledModules as runInstalledModuleRescan
import me.weishu.kernelsu.ui.util.securelyRemoveModule as runSecureModuleRemoval
import org.json.JSONObject

class SecurityAuditViewModel : ViewModel() {
    private val _uiState = MutableStateFlow(SecurityAuditUiState())
    val uiState: StateFlow<SecurityAuditUiState> = _uiState.asStateFlow()
    private var refreshJob: Job? = null
    private val checkpointStore by lazy { ModuleAuditCheckpointStore(ksuApp) }

    fun refresh() {
        refreshJob?.cancel()
        while (true) {
            val state = _uiState.value
            if (state.isRescanning || state.isPruning) return
            if (
                _uiState.compareAndSet(
                    state,
                    state.copy(
                        isLoading = state.histories.isEmpty(),
                        isRefreshing = state.histories.isNotEmpty(),
                        errorMessage = null,
                    ),
                )
            ) {
                break
            }
        }
        refreshJob = viewModelScope.launch(Dispatchers.IO) {
            runCatching {
                val checkpointResult = runCatching { getModuleAuditCheckpoint() }
                val rawHistoryResult = runCatching { getModuleAuditHistories() }
                val sealedEnvelopeHash = runCatching {
                    JSONObject(getModuleAuditSealStatus())
                        .optString("seal_hash")
                        .takeIf(String::isNotBlank)
                }.getOrNull()
                val historyResult = rawHistoryResult.mapCatching(::parseAuditHistories)
                checkpointResult.exceptionOrNull()?.let { if (it is CancellationException) throw it }
                historyResult.exceptionOrNull()?.let { if (it is CancellationException) throw it }
                var checkpoint = checkpointResult.fold(
                    onSuccess = { payload ->
                        checkpointStore.reconcile(
                            payload,
                            rawHistoryResult.getOrNull(),
                            sealedEnvelopeHash,
                        )
                    },
                    onFailure = { error ->
                        checkpointStore.checkpointUnavailable(
                            error.message ?: error::class.java.simpleName
                        )
                    },
                )
                val histories = historyResult.getOrDefault(emptyList())
                    .map { history ->
                        history.copy(
                            status = history.status.copy(
                                managerCheckpoint = checkpoint.trust.wireName
                            )
                        )
                    }
                    .sortedWith(
                        compareByDescending<AuditHistory> { it.isHighRisk() }
                            .thenByDescending { history ->
                                history.events.maxOfOrNull { it.timestampUnixSeconds } ?: 0L
                            }
                    )
                val staleResult = runCatching {
                    parseStaleAuditModuleIds(getStaleModuleAuditHistories())
                }
                staleResult.exceptionOrNull()?.let { if (it is CancellationException) throw it }
                val authorizationResult = if (
                    checkpoint.trust == AuditCheckpointTrust.Initialized ||
                    checkpoint.trust == AuditCheckpointTrust.Verified
                ) {
                    runCatching { ensureAuditAuthorization() }
                } else {
                    Result.success(false)
                }
                authorizationResult.exceptionOrNull()?.let {
                    if (it is CancellationException) throw it
                }
                val sealResult = authorizationResult.mapCatching { authorizationReady ->
                    if (authorizationReady) ensureAuditSeal() else false
                }
                sealResult.exceptionOrNull()?.let { error ->
                    if (error is CancellationException) throw error
                    checkpoint = checkpointStore.externalIntegrityFailure(
                        error.message ?: error::class.java.simpleName
                    )
                }
                AuditLoadResult(
                    histories = histories,
                    staleModuleIds = staleResult.getOrDefault(emptyList()),
                    checkpoint = checkpoint,
                    authorizationReady = sealResult.getOrDefault(false),
                    error = historyResult.exceptionOrNull()
                        ?: staleResult.exceptionOrNull()
                        ?: sealResult.exceptionOrNull()
                        ?: authorizationResult.exceptionOrNull(),
                )
            }.onSuccess { result ->
                _uiState.value = SecurityAuditUiState(
                    isLoading = false,
                    isRescanning = _uiState.value.isRescanning,
                    isPruning = _uiState.value.isPruning,
                    isRecovering = _uiState.value.isRecovering,
                    histories = result.histories,
                    staleModuleIds = result.staleModuleIds,
                    checkpointCompromised =
                        result.checkpoint.trust == AuditCheckpointTrust.Compromised,
                    checkpointIncident = result.checkpoint
                        .takeIf { it.trust == AuditCheckpointTrust.Compromised }
                        ?.detail,
                    recoverableModuleIds = result.checkpoint.recoverableModules,
                    recoverySafeMode = Natives.isSafeMode,
                    keyProtection = result.checkpoint.protection,
                    auditAuthorizationReady = result.authorizationReady,
                    errorMessage = result.error?.let {
                        it.message ?: it::class.java.simpleName
                    },
                )
            }.onFailure { error ->
                if (error is CancellationException) throw error
                _uiState.update {
                    it.copy(
                        isLoading = false,
                        isRefreshing = false,
                        errorMessage = error.message ?: error::class.java.simpleName,
                    )
                }
            }
        }
    }

    private data class AuditLoadResult(
        val histories: List<AuditHistory>,
        val staleModuleIds: List<String>,
        val checkpoint: AuditCheckpointVerification,
        val authorizationReady: Boolean,
        val error: Throwable?,
    )

    private suspend fun ensureAuditAuthorization(): Boolean {
        val publicKey = checkpointStore.authorizationPublicKeyHex()
        val ownKeyId = checkpointStore.authorizationKeyId()
        val statusResult = runCatching {
            JSONObject(getModuleAuditAuthorizationStatus())
        }
        val status = statusResult.getOrNull()
        val configured = status?.optBoolean("configured", false) == true
        val registeredKeyId = status?.optString("key_id")?.takeIf(String::isNotBlank)

        if (status != null && !configured) {
            val registered = JSONObject(
                registerModuleAuditAuthorizationKey(publicKey, recover = false)
            )
            check(registered.optString("key_id") == ownKeyId) {
                "ksud registered an unexpected Manager audit authorization key"
            }
            return true
        }
        if (configured && registeredKeyId == ownKeyId) return true

        if (Natives.isSafeMode) {
            val recovered = JSONObject(
                registerModuleAuditAuthorizationKey(publicKey, recover = true)
            )
            check(recovered.optString("key_id") == ownKeyId) {
                "ksud recovered an unexpected Manager audit authorization key"
            }
            return true
        }

        statusResult.exceptionOrNull()?.let { cause ->
            throw IllegalStateException(
                ksuApp.getString(R.string.security_audit_authorization_unavailable),
                cause,
            )
        }
        error(ksuApp.getString(R.string.security_audit_authorization_changed))
    }

    private suspend fun createAuthorization(action: String, moduleId: String? = null): String =
        checkpointStore.signAuditAuthorization(
            getModuleAuditAuthorizationChallenge(action, moduleId)
        )

    private suspend fun ensureAuditSeal(): Boolean {
        val status = JSONObject(getModuleAuditSealStatus())
        val configured = status.optBoolean("configured", false)
        val sealedHash = status.optString("seal_hash").takeIf(String::isNotBlank)
        val currentHash = checkpointStore.currentSealHash()
        val previousHash = checkpointStore.acceptablePreviousSealHash()
        if (!requiresAuditSealCommit(configured, sealedHash, currentHash, previousHash)) {
            checkpointStore.markSealSynchronized(currentHash)
            return true
        }

        val committed = JSONObject(
            commitModuleAuditSeal(checkpointStore.currentSealEnvelopeHex())
        )
        check(committed.optBoolean("configured", false)) {
            "ksud did not persist the Manager audit seal"
        }
        check(committed.optString("seal_hash") == currentHash) {
            "ksud persisted an unexpected Manager audit seal"
        }
        checkpointStore.markSealSynchronized(currentHash)
        return true
    }

    fun recoverCheckpointAfterChainRebuild() {
        while (true) {
            val state = _uiState.value
            if (
                state.isRecovering ||
                state.isRescanning ||
                state.isPruning ||
                !state.checkpointCompromised ||
                state.recoverableModuleIds.isEmpty()
            ) {
                return
            }
            if (!Natives.isSafeMode) {
                _uiState.update {
                    it.copy(errorMessage = ksuApp.getString(R.string.security_audit_recovery_safe_mode))
                }
                return
            }
            if (
                _uiState.compareAndSet(
                    state,
                    state.copy(isRecovering = true, errorMessage = null),
                )
            ) {
                break
            }
        }
        viewModelScope.launch(Dispatchers.IO) {
            runCatching {
                val recovery = checkpointStore.acceptRecoveredChain(
                    getModuleAuditCheckpoint(),
                    getModuleAuditHistories(),
                )
                check(recovery.trust == AuditCheckpointTrust.Verified) {
                    recovery.detail ?: "Unable to accept rebuilt audit chain"
                }
            }.onFailure { error ->
                if (error is CancellationException) throw error
                _uiState.update {
                    it.copy(errorMessage = error.message ?: error::class.java.simpleName)
                }
            }
            _uiState.update { it.copy(isRecovering = false) }
            refresh()
        }
    }

    fun rescanInstalledModules() {
        while (true) {
            val state = _uiState.value
            if (
                state.isRescanning ||
                state.isPruning ||
                state.auditMutationBlocked
            ) {
                return
            }
            if (
                _uiState.compareAndSet(
                    state,
                    state.copy(isRescanning = true, errorMessage = null),
                )
            ) {
                break
            }
        }
        viewModelScope.launch(Dispatchers.IO) {
            runCatching {
                runInstalledModuleRescan(createAuthorization("rescan"))
            }.onFailure { error ->
                if (error is CancellationException) throw error
                _uiState.update {
                    it.copy(errorMessage = error.message ?: error::class.java.simpleName)
                }
            }
            _uiState.update { it.copy(isRescanning = false) }
            refresh()
        }
    }

    fun pruneStaleAuditHistories() {
        while (true) {
            val state = _uiState.value
            if (
                state.isPruning ||
                state.isRescanning ||
                state.auditMutationBlocked ||
                state.staleModuleIds.isEmpty()
            ) {
                return
            }
            if (
                _uiState.compareAndSet(
                    state,
                    state.copy(isPruning = true, errorMessage = null),
                )
            ) {
                break
            }
        }
        viewModelScope.launch(Dispatchers.IO) {
            val result = runCatching {
                pruneStaleModuleAuditHistories(createAuthorization("prune"))
            }
            result.onFailure { error ->
                if (error is CancellationException) throw error
                _uiState.update {
                    it.copy(
                        isPruning = false,
                        errorMessage = error.message ?: error::class.java.simpleName,
                    )
                }
            }
            if (result.isSuccess) {
                _uiState.update { it.copy(isPruning = false) }
                refresh()
            }
        }
    }

    fun containForSecureRemoval(moduleId: String, onContained: () -> Unit) {
        val history = _uiState.value.histories.firstOrNull { it.status.moduleId == moduleId }
        if (history?.status?.unresolvedRisk != true || moduleId in _uiState.value.staleModuleIds) {
            return
        }
        viewModelScope.launch {
            runCatching {
                withContext(Dispatchers.IO) { containModuleForSecureRemoval(moduleId) }
            }.onSuccess {
                onContained()
            }.onFailure { error ->
                if (error is CancellationException) throw error
                _uiState.update {
                    it.copy(errorMessage = error.message ?: error::class.java.simpleName)
                }
            }
        }
    }

    fun securelyRemoveModule(moduleId: String) {
        while (true) {
            val state = _uiState.value
            val history = state.histories.firstOrNull { it.status.moduleId == moduleId }
            if (
                state.secureRemovalModuleId != null || state.auditMutationBlocked ||
                !state.recoverySafeMode || history?.status?.unresolvedRisk != true ||
                moduleId in state.staleModuleIds
            ) {
                return
            }
            if (_uiState.compareAndSet(state, state.copy(secureRemovalModuleId = moduleId))) break
        }
        viewModelScope.launch(Dispatchers.IO) {
            runCatching {
                runSecureModuleRemoval(moduleId, createAuthorization("secure-remove", moduleId))
            }.onFailure { error ->
                if (error is CancellationException) throw error
                _uiState.update {
                    it.copy(errorMessage = error.message ?: error::class.java.simpleName)
                }
            }
            _uiState.update { it.copy(secureRemovalModuleId = null) }
            refresh()
        }
    }
}
