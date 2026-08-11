package me.weishu.kernelsu.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext
import me.weishu.kernelsu.Natives
import me.weishu.kernelsu.R
import me.weishu.kernelsu.ksuApp
import me.weishu.kernelsu.security.AuditCheckpointTrust
import me.weishu.kernelsu.security.AuditCheckpointVerification
import me.weishu.kernelsu.security.AuditDashboardCache
import me.weishu.kernelsu.security.ModuleAuditCheckpointStore
import me.weishu.kernelsu.security.requiresAuditSealCommit
import me.weishu.kernelsu.ui.screen.securityaudit.AuditHistory
import me.weishu.kernelsu.ui.screen.securityaudit.SecurityAuditUiState
import me.weishu.kernelsu.ui.screen.securityaudit.SecureRemovalPhase
import me.weishu.kernelsu.ui.screen.securityaudit.isHighRisk
import me.weishu.kernelsu.ui.screen.securityaudit.parseAuditHistories
import me.weishu.kernelsu.ui.util.commitModuleAuditSeal
import me.weishu.kernelsu.ui.util.containModuleForSecureRemoval
import me.weishu.kernelsu.ui.util.getModuleAuditHistories
import me.weishu.kernelsu.ui.util.getModuleAuditRecoveryStatus
import me.weishu.kernelsu.ui.util.getModuleAuditCheckpoint
import me.weishu.kernelsu.ui.util.getModuleAuditAuthorizationChallenge
import me.weishu.kernelsu.ui.util.getModuleAuditAuthorizationStatus
import me.weishu.kernelsu.ui.util.getModuleAuditSealStatus
import me.weishu.kernelsu.ui.util.listModules
import me.weishu.kernelsu.ui.util.pruneStaleModuleAuditHistories
import me.weishu.kernelsu.ui.util.registerModuleAuditAuthorizationKey
import me.weishu.kernelsu.ui.util.recoverManagerSealedAudit
import me.weishu.kernelsu.ui.util.rescanInstalledModules as runInstalledModuleRescan
import me.weishu.kernelsu.ui.util.securelyRemoveModule as runSecureModuleRemoval
import me.weishu.kernelsu.ui.util.streamModuleAuditDashboard
import me.weishu.kernelsu.ui.util.waitForModuleAuditDashboardChange
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.atomic.AtomicLong

class SecurityAuditViewModel : ViewModel() {
    private val _uiState = MutableStateFlow(SecurityAuditUiState())
    val uiState: StateFlow<SecurityAuditUiState> = _uiState.asStateFlow()
    private var refreshJob: Job? = null
    private var watchJob: Job? = null
    private val refreshGeneration = AtomicLong()
    private val checkpointStore by lazy { ModuleAuditCheckpointStore(ksuApp) }

    private data class DashboardStreamResult(
        val rawHistories: String,
        val completion: JSONObject,
    )

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
            it.copy(status = it.status.copy(managerCheckpoint = AuditCheckpointTrust.Verified.wireName))
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

    private suspend fun loadDashboardStream(generation: Long): DashboardStreamResult {
        val histories = linkedMapOf<String, JSONObject>()
        var completion: JSONObject? = null
        streamModuleAuditDashboard { rawLine ->
            if (refreshGeneration.get() != generation) return@streamModuleAuditDashboard
            val line = JSONObject(rawLine)
            when (line.getString("type")) {
                "start" -> _uiState.update {
                    it.copy(
                        isLoading = it.histories.isEmpty(),
                        isRefreshing = it.histories.isNotEmpty(),
                        verificationModuleId = null,
                        verificationCompleted = 0,
                        verificationTotal = line.getInt("total_modules"),
                    )
                }
                "module" -> {
                    val moduleId = line.getString("module_id")
                    val rawHistory = line.getJSONObject("history")
                    histories[moduleId] = rawHistory
                    val history = parseAuditHistories(JSONArray().put(rawHistory).toString()).single()
                    _uiState.update { state ->
                        val merged = state.histories
                            .associateBy { it.status.moduleId }
                            .toMutableMap()
                            .apply { put(moduleId, history) }
                        state.copy(
                            isLoading = false,
                            isRefreshing = true,
                            verificationModuleId = moduleId,
                            verificationCompleted = line.getInt("completed"),
                            verificationTotal = line.getInt("total_modules"),
                            histories = sortedHistories(merged.values),
                            checkpointCompromised = state.checkpointCompromised ||
                                history.status.unresolvedRisk,
                            checkpointIncident = history.integrityError ?: state.checkpointIncident,
                        )
                    }
                }
                "progress" -> _uiState.update {
                    it.copy(
                        verificationModuleId = null,
                        verificationCompleted = line.getInt("completed"),
                        verificationTotal = line.getInt("total_modules"),
                    )
                }
                "error" -> _uiState.update {
                    it.copy(
                        checkpointCompromised = true,
                        checkpointIncident = line.optString("error"),
                    )
                }
                "complete" -> completion = line
            }
        }
        if (refreshGeneration.get() != generation) throw CancellationException()
        return DashboardStreamResult(
            rawHistories = JSONArray(histories.values).toString(),
            completion = checkNotNull(completion) { "ksud dashboard verification did not complete" },
        )
    }

    fun refresh() {
        refreshJob?.cancel()
        watchJob?.cancel()
        val generation = refreshGeneration.incrementAndGet()
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
            ) {
                break
            }
        }
        refreshJob = viewModelScope.launch(Dispatchers.IO) {
            checkpointStore.readDashboardCache()?.let(::applyCachedDashboard)
            runCatching {
                val stream = loadDashboardStream(generation)
                val completion = stream.completion
                if (completion.optBoolean("uninitialized", false)) {
                    val checkpoint = checkpointStore.checkpointUnavailable(
                        "Module audit history is not initialized"
                    )
                    return@runCatching AuditLoadResult(
                        histories = emptyList(),
                        staleModuleIds = emptyList(),
                        checkpoint = checkpoint,
                        initialized = false,
                        authorizationReady = false,
                        sealedRecoveryModuleIds = emptyList(),
                        storeRevision = completion.getString("store_revision"),
                        error = null,
                    )
                }
                val rawCheckpoint = completion.getJSONObject("checkpoint").toString()
                val sealStatus = completion.getJSONObject("seal_status")
                val authorizationStatus = completion.getJSONObject("authorization_status")
                val sealedEnvelopeHash = sealStatus.optString("seal_hash")
                    .takeIf(String::isNotBlank)
                var checkpoint = checkpointStore.reconcile(
                    rawCheckpoint,
                    stream.rawHistories,
                    sealedEnvelopeHash,
                )
                val sealedRecoveryModuleIds = checkpoint.recoverableModules
                val histories = sortedHistories(
                    parseAuditHistories(stream.rawHistories).map { history ->
                        history.copy(
                            status = history.status.copy(
                                managerCheckpoint = checkpoint.trust.wireName
                            )
                        )
                    }
                )
                val staleModuleIds = completion.getJSONArray("stale_histories").moduleIds()
                val authorizationResult = if (
                    checkpoint.trust == AuditCheckpointTrust.Initialized ||
                    checkpoint.trust == AuditCheckpointTrust.Verified
                ) {
                    runCatching { ensureAuditAuthorization(authorizationStatus) }
                } else {
                    Result.success(false)
                }
                authorizationResult.exceptionOrNull()?.let {
                    if (it is CancellationException) throw it
                }
                val sealResult = authorizationResult.mapCatching { authorizationReady ->
                    if (authorizationReady) ensureAuditSeal(sealStatus) else false
                }
                sealResult.exceptionOrNull()?.let { error ->
                    if (error is CancellationException) throw error
                    checkpoint = checkpointStore.externalIntegrityFailure(
                        error.message ?: error::class.java.simpleName
                    )
                }
                if (sealResult.getOrDefault(false) &&
                    checkpoint.trust != AuditCheckpointTrust.Compromised
                ) {
                    checkpointStore.writeDashboardCache(
                        JSONObject()
                            .put("histories", JSONArray(stream.rawHistories))
                            .put("stale_module_ids", JSONArray(staleModuleIds))
                            .put("key_protection", checkpoint.protection.wireName)
                            .toString()
                    )
                }
                AuditLoadResult(
                    histories = histories,
                    staleModuleIds = staleModuleIds,
                    checkpoint = checkpoint,
                    authorizationReady = sealResult.getOrDefault(false),
                    sealedRecoveryModuleIds = sealedRecoveryModuleIds,
                    storeRevision = completion.getString("store_revision"),
                    error = sealResult.exceptionOrNull() ?: authorizationResult.exceptionOrNull(),
                )
            }.onSuccess { result ->
                if (refreshGeneration.get() != generation) return@onSuccess
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
                    sealedRecoveryModuleIds = result.sealedRecoveryModuleIds,
                    recoverySafeMode = Natives.isSafeMode,
                    auditInitialized = result.initialized,
                    keyProtection = result.checkpoint.protection,
                    auditAuthorizationReady = result.authorizationReady,
                    errorMessage = result.error?.let {
                        it.message ?: it::class.java.simpleName
                    },
                )
                startDashboardWatch(result.storeRevision)
            }.onFailure { error ->
                if (error is CancellationException) throw error
                if (refreshGeneration.get() != generation) return@onFailure
                val sealedRecoveryModuleIds = runCatching {
                    JSONObject(getModuleAuditRecoveryStatus())
                        .getJSONArray("failures")
                        .moduleIds()
                }.getOrDefault(emptyList())
                _uiState.update {
                    it.copy(
                        isLoading = false,
                        isRefreshing = false,
                        verificationModuleId = null,
                        recoverableModuleIds = sealedRecoveryModuleIds,
                        sealedRecoveryModuleIds = sealedRecoveryModuleIds,
                        checkpointCompromised = it.checkpointCompromised ||
                            sealedRecoveryModuleIds.isNotEmpty(),
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
        val initialized: Boolean = true,
        val authorizationReady: Boolean,
        val sealedRecoveryModuleIds: List<String>,
        val storeRevision: String,
        val error: Throwable?,
    )

    private fun startDashboardWatch(initialRevision: String) {
        watchJob?.cancel()
        watchJob = viewModelScope.launch(Dispatchers.IO) {
            while (isActive) {
                val changed = runCatching {
                    waitForModuleAuditDashboardChange(initialRevision)
                }.getOrElse {
                    delay(1_000)
                    false
                }
                if (changed) {
                    viewModelScope.launch { refresh() }
                    return@launch
                }
            }
        }
    }

    private suspend fun ensureAuditAuthorization(prefetchedStatus: JSONObject? = null): Boolean {
        val publicKey = checkpointStore.authorizationPublicKeyHex()
        val ownKeyId = checkpointStore.authorizationKeyId()
        val statusResult = prefetchedStatus?.let { Result.success(it) } ?: runCatching {
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

    private suspend fun ensureAuditSeal(prefetchedStatus: JSONObject? = null): Boolean {
        val status = prefetchedStatus ?: JSONObject(getModuleAuditSealStatus())
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
                recoverSealedHistories(_uiState.value.sealedRecoveryModuleIds)
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
        var sealedRecoveryModuleIds = emptyList<String>()
        while (true) {
            val state = _uiState.value
            val history = state.histories.firstOrNull { it.status.moduleId == moduleId }
            val canRecoverSealedDamage =
                state.checkpointCompromised && moduleId in state.sealedRecoveryModuleIds
            if (
                state.secureRemovalModuleId != null || state.isLoading || state.isRefreshing ||
                state.isRecovering ||
                !state.recoverySafeMode || history?.status?.unresolvedRisk != true ||
                moduleId in state.staleModuleIds ||
                (state.checkpointCompromised && !canRecoverSealedDamage) ||
                (!state.auditAuthorizationReady && !canRecoverSealedDamage)
            ) {
                return
            }
            sealedRecoveryModuleIds = if (canRecoverSealedDamage) {
                state.sealedRecoveryModuleIds
            } else {
                emptyList()
            }
            val initialPhase = if (sealedRecoveryModuleIds.isNotEmpty()) {
                SecureRemovalPhase.RecoveringAudit
            } else {
                SecureRemovalPhase.RemovingModule
            }
            if (
                _uiState.compareAndSet(
                    state,
                    state.copy(
                        secureRemovalModuleId = moduleId,
                        secureRemovalPhase = initialPhase,
                        errorMessage = null,
                    ),
                )
            ) break
        }
        viewModelScope.launch(Dispatchers.IO) {
            val result = runCatching {
                if (sealedRecoveryModuleIds.isNotEmpty()) {
                    recoverSealedHistories(sealedRecoveryModuleIds, trackSecureRemoval = true)
                }
                _uiState.update { it.copy(secureRemovalPhase = SecureRemovalPhase.RemovingModule) }
                runSecureModuleRemoval(moduleId, createAuthorization("secure-remove", moduleId))
                _uiState.update { it.copy(secureRemovalPhase = SecureRemovalPhase.RefreshingModules) }
                val modules = JSONArray(listModules())
                check((0 until modules.length()).none { index ->
                    modules.getJSONObject(index).optString("id") == moduleId
                }) {
                    "Secure removal completed but the module is still present"
                }
            }
            result.onSuccess {
                _uiState.update { it.copy(secureRemovalPhase = SecureRemovalPhase.Completed) }
            }.onFailure { error ->
                if (error is CancellationException) throw error
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

    private suspend fun recoverSealedHistories(
        moduleIds: List<String>,
        trackSecureRemoval: Boolean = false,
    ) {
        if (trackSecureRemoval) {
            _uiState.update { it.copy(secureRemovalPhase = SecureRemovalPhase.RecoveringAudit) }
        }
        ensureAuditAuthorization()
        for (moduleId in moduleIds) {
            val challenge = getModuleAuditAuthorizationChallenge("recover-sealed", moduleId)
            val authorization = checkpointStore.signSealedRecoveryAuthorization(challenge)
            recoverManagerSealedAudit(moduleId, authorization)
        }
        if (trackSecureRemoval) {
            _uiState.update { it.copy(secureRemovalPhase = SecureRemovalPhase.AnchoringAudit) }
        }
        val recovery = checkpointStore.acceptRecoveredChain(
            getModuleAuditCheckpoint(),
            getModuleAuditHistories(),
        )
        check(recovery.trust == AuditCheckpointTrust.Verified) {
            recovery.detail ?: "Unable to accept rebuilt audit chain"
        }
        check(ensureAuditAuthorization()) {
            "Manager audit authorization is unavailable after recovery"
        }
        check(ensureAuditSeal()) {
            "Unable to anchor the recovered audit chain"
        }
    }
}

private fun JSONArray.moduleIds(): List<String> = buildList {
    for (index in 0 until length()) {
        val moduleId = getJSONObject(index).getString("module_id")
        check(moduleId.matches(Regex("^[A-Za-z][A-Za-z0-9._-]+$"))) {
            "Invalid sealed recovery module id"
        }
        add(moduleId)
    }
}.distinct().sorted()
