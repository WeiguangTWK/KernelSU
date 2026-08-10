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
import me.weishu.kernelsu.Natives
import me.weishu.kernelsu.R
import me.weishu.kernelsu.ksuApp
import me.weishu.kernelsu.security.AuditCheckpointTrust
import me.weishu.kernelsu.security.AuditCheckpointVerification
import me.weishu.kernelsu.security.ModuleAuditCheckpointStore
import me.weishu.kernelsu.ui.screen.securityaudit.AuditHistory
import me.weishu.kernelsu.ui.screen.securityaudit.SecurityAuditUiState
import me.weishu.kernelsu.ui.screen.securityaudit.isHighRisk
import me.weishu.kernelsu.ui.screen.securityaudit.parseAuditHistories
import me.weishu.kernelsu.ui.screen.securityaudit.parseStaleAuditModuleIds
import me.weishu.kernelsu.ui.util.getModuleAuditHistories
import me.weishu.kernelsu.ui.util.getModuleAuditCheckpoint
import me.weishu.kernelsu.ui.util.getModuleAuditAuthorizationChallenge
import me.weishu.kernelsu.ui.util.getModuleAuditAuthorizationStatus
import me.weishu.kernelsu.ui.util.getStaleModuleAuditHistories
import me.weishu.kernelsu.ui.util.pruneStaleModuleAuditHistories
import me.weishu.kernelsu.ui.util.registerModuleAuditAuthorizationKey
import me.weishu.kernelsu.ui.util.rescanInstalledModules as runInstalledModuleRescan
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
                val historyResult = runCatching { parseAuditHistories(getModuleAuditHistories()) }
                checkpointResult.exceptionOrNull()?.let { if (it is CancellationException) throw it }
                historyResult.exceptionOrNull()?.let { if (it is CancellationException) throw it }
                val checkpoint = checkpointResult.fold(
                    onSuccess = checkpointStore::reconcile,
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
                AuditLoadResult(
                    histories = histories,
                    staleModuleIds = staleResult.getOrDefault(emptyList()),
                    checkpoint = checkpoint,
                    authorizationReady = authorizationResult.getOrDefault(false),
                    error = historyResult.exceptionOrNull()
                        ?: staleResult.exceptionOrNull()
                        ?: authorizationResult.exceptionOrNull(),
                )
            }.onSuccess { result ->
                _uiState.value = SecurityAuditUiState(
                    isLoading = false,
                    isRescanning = _uiState.value.isRescanning,
                    isPruning = _uiState.value.isPruning,
                    histories = result.histories,
                    staleModuleIds = result.staleModuleIds,
                    checkpointCompromised =
                        result.checkpoint.trust == AuditCheckpointTrust.Compromised,
                    checkpointIncident = result.checkpoint
                        .takeIf { it.trust == AuditCheckpointTrust.Compromised }
                        ?.detail,
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

    private suspend fun createAuthorization(action: String): String =
        checkpointStore.signAuditAuthorization(
            getModuleAuditAuthorizationChallenge(action)
        )

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
}
