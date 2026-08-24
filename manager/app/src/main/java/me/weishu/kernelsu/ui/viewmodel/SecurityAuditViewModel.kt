package me.weishu.kernelsu.ui.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import me.weishu.kernelsu.R
import me.weishu.kernelsu.ksuApp
import me.weishu.kernelsu.security.AuditCheckpointTrust
import me.weishu.kernelsu.security.AuditCheckpointVerification
import me.weishu.kernelsu.security.AuditDashboardCache
import me.weishu.kernelsu.security.AuditAssessment
import me.weishu.kernelsu.security.AuditTransactionCommits
import me.weishu.kernelsu.security.AuditTransactionReceipt
import me.weishu.kernelsu.security.AuditInventoryRelation
import me.weishu.kernelsu.security.AuditModuleDisposition
import me.weishu.kernelsu.security.ModuleAuditCheckpointStore
import me.weishu.kernelsu.security.AuditEmergencyStatus
import me.weishu.kernelsu.security.parseModuleAuditResponseStatus
import me.weishu.kernelsu.security.parseAuditAssessment
import me.weishu.kernelsu.security.requiresAuditSealCommit
import me.weishu.kernelsu.security.sealModuleAuditSession
import me.weishu.kernelsu.ui.screen.securityaudit.AuditHistory
import me.weishu.kernelsu.ui.screen.securityaudit.SecurityAuditUiState
import me.weishu.kernelsu.ui.screen.securityaudit.SecureRemovalPhase
import me.weishu.kernelsu.ui.screen.securityaudit.isHighRisk
import me.weishu.kernelsu.ui.screen.securityaudit.parseAuditHistories
import me.weishu.kernelsu.ui.util.commitModuleAuditSeal
import me.weishu.kernelsu.ui.util.closeModuleAuditIncident
import me.weishu.kernelsu.ui.util.beginAuditInstallSession
import me.weishu.kernelsu.ui.util.containModuleForSecureRemoval
import me.weishu.kernelsu.ui.util.deleteQuarantinedAuditScript
import me.weishu.kernelsu.ui.util.getModuleAuditHistories
import me.weishu.kernelsu.ui.util.getModuleAuditRecoveryStatus
import me.weishu.kernelsu.ui.util.getModuleAuditResponseStatus
import me.weishu.kernelsu.ui.util.getModuleAuditCheckpoint
import me.weishu.kernelsu.ui.util.getModuleAuditAuthorizationChallenge
import me.weishu.kernelsu.ui.util.getModuleAuditAuthorizationStatus
import me.weishu.kernelsu.ui.util.getModuleAuditSealStatus
import me.weishu.kernelsu.ui.util.pruneStaleModuleAuditHistories
import me.weishu.kernelsu.ui.util.registerModuleAuditAuthorizationKey
import me.weishu.kernelsu.ui.util.recoverManagerSealedAudit
import me.weishu.kernelsu.ui.util.reconcileModuleAuditResponse
import me.weishu.kernelsu.ui.util.releaseAuditInstallSession
import me.weishu.kernelsu.ui.util.retryQuarantinedAuditScriptContainment
import me.weishu.kernelsu.ui.util.rescanInstalledModules as runInstalledModuleRescan
import me.weishu.kernelsu.ui.util.securelyRemoveModule as runSecureModuleRemoval
import me.weishu.kernelsu.ui.util.streamModuleAuditDashboard
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.atomic.AtomicLong

class SecurityAuditViewModel : ViewModel() {
    private class AuditPostCommitFailure(
        val receipts: List<AuditTransactionReceipt>,
        cause: Throwable,
    ) : IllegalStateException(
        "Audit transaction ${receipts.joinToString { it.operationId }} committed, " +
            "but Manager synchronization failed: " +
            (cause.message ?: cause::class.java.simpleName),
        cause,
    )

    private val _uiState = MutableStateFlow(SecurityAuditUiState())
    val uiState: StateFlow<SecurityAuditUiState> = _uiState.asStateFlow()
    private var refreshJob: Job? = null
    private val refreshGeneration = AtomicLong()
    private val checkpointStore by lazy { ModuleAuditCheckpointStore(ksuApp) }

    private suspend fun <T> withAuditMutationSession(
        block: suspend (String, MutableCollection<AuditTransactionReceipt>) -> T,
    ): T {
        val session = beginAuditInstallSession(timeoutSeconds = 600)
        val committedReceipts = mutableListOf<AuditTransactionReceipt>()
        var primaryFailure: Throwable? = null
        try {
            val result = block(session, committedReceipts)
            sealModuleAuditSession(session, checkpointStore)
            reconcileModuleAuditResponse()
            return result
        } catch (error: Throwable) {
            val propagated = if (
                error is CancellationException || committedReceipts.isEmpty()
            ) {
                error
            } else {
                AuditPostCommitFailure(committedReceipts.toList(), error)
            }
            primaryFailure = propagated
            throw propagated
        } finally {
            var finalizationFailure: Throwable? = null
            withContext(NonCancellable) {
                runCatching {
                    releaseAuditInstallSession(session)
                }.onFailure { finalizationFailure = it }
                committedReceipts
                    .distinctBy(AuditTransactionReceipt::operationId)
                    .forEach { receipt ->
                        runCatching { AuditTransactionCommits.publish(receipt) }
                            .onFailure { publishFailure ->
                                finalizationFailure?.addSuppressed(publishFailure)
                                    ?: run { finalizationFailure = publishFailure }
                            }
                    }
            }
            finalizationFailure?.let { error ->
                val failure = primaryFailure
                if (failure == null) {
                    throw if (committedReceipts.isEmpty()) {
                        error
                    } else {
                        AuditPostCommitFailure(committedReceipts.toList(), error)
                    }
                }
                failure.addSuppressed(error)
            }
        }
    }

    private fun MutableCollection<AuditTransactionReceipt>.record(
        receipt: AuditTransactionReceipt,
        expectedAction: String,
        expectedTarget: String? = null,
    ) {
        add(receipt)
        check(receipt.action == expectedAction) {
            "Audit transaction action mismatch: ${receipt.action}"
        }
        check(expectedTarget == null || receipt.targets == listOf(expectedTarget)) {
            "Audit transaction target mismatch: ${receipt.targets.joinToString()}"
        }
    }

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
                                history.integrityError != null,
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
            val initialResponseStatus = runCatching {
                parseModuleAuditResponseStatus(getModuleAuditResponseStatus())
            }.getOrNull()
            val recoverySafeMode = initialResponseStatus?.kernelSafeMode ?: false
            runCatching {
                val stream = loadDashboardStream(generation)
                val completion = stream.completion
                val responseStatus = parseModuleAuditResponseStatus(getModuleAuditResponseStatus())
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
                        assessment = null,
                        sealedRecoveryModuleIds = emptyList(),
                        emergencyStatus = responseStatus.emergency,
                        storeRevision = completion.getString("store_revision"),
                        error = null,
                    )
                }
                val assessment = parseAuditAssessment(completion.getJSONObject("assessment"))
                check(assessment.snapshotRevision == completion.getString("store_revision")) {
                    "Audit assessment revision does not match its snapshot"
                }
                check(assessment.unauditedModuleIds.isEmpty()) {
                    "Installed modules are missing from the verified audit inventory: " +
                        assessment.unauditedModuleIds.joinToString()
                }
                check(assessment.unsealedModuleIds.isEmpty()) {
                    "Module audit histories are not Manager-sealed: " +
                        assessment.unsealedModuleIds.joinToString()
                }
                val rawCheckpointObject = completion.getJSONObject("checkpoint")
                check(assessment.inventoryHash == rawCheckpointObject.getString("inventory_hash")) {
                    "Audit assessment inventory does not match its checkpoint"
                }
                val inventoryRelation = assessment.inventoryRelation
                val checkpointDegraded = completion.optBoolean("checkpoint_degraded", false)
                check(checkpointDegraded == (inventoryRelation == AuditInventoryRelation.SealedDamage)) {
                    "Audit snapshot relation does not match its integrity state"
                }
                val rawCheckpoint = rawCheckpointObject.toString()
                val sealStatus = completion.getJSONObject("seal_status")
                val authorizationStatus = completion.getJSONObject("authorization_status")
                val sealedEnvelopeHash = sealStatus.optString("seal_hash")
                    .takeIf(String::isNotBlank)
                var checkpoint = checkpointStore.reconcile(
                    rawCheckpoint,
                    stream.rawHistories,
                    sealedEnvelopeHash,
                )
                if (
                    checkpointDegraded &&
                    checkpoint.trust != AuditCheckpointTrust.Compromised
                ) {
                    val recoverableModules = completion
                        .getJSONArray("integrity_failures")
                        .moduleIds()
                    check(recoverableModules.isNotEmpty()) {
                        "Degraded audit checkpoint has no integrity failures"
                    }
                    checkpoint = checkpoint.copy(
                        trust = AuditCheckpointTrust.Compromised,
                        detail = "Manager-sealed audit histories require recovery: " +
                            recoverableModules.joinToString(),
                        recoverableModules = recoverableModules,
                    )
                }
                val sealedRecoveryModuleIds = assessment.sealedRecoveryModuleIds
                check(sealedRecoveryModuleIds.toSet() == checkpoint.recoverableModules.toSet()) {
                    "Audit assessment recovery set does not match the verified checkpoint"
                }
                val histories = sortedHistories(
                    parseAuditHistories(stream.rawHistories).map { history ->
                        history.copy(
                            status = history.status.copy(
                                managerCheckpoint = checkpoint.trust.wireName
                            )
                        )
                    }
                )
                val staleModuleIds = assessment.staleModuleIds
                val authorizationResult = if (
                    checkpoint.trust == AuditCheckpointTrust.Initialized ||
                    checkpoint.trust == AuditCheckpointTrust.Verified
                ) {
                    runCatching {
                        ensureAuditAuthorization(authorizationStatus, recoverySafeMode)
                    }
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
                    assessment = assessment,
                    sealedRecoveryModuleIds = sealedRecoveryModuleIds,
                    emergencyStatus = responseStatus.emergency,
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
                    recoverySafeMode = result.assessment?.kernelSafeMode ?: recoverySafeMode,
                    auditInitialized = result.initialized,
                    keyProtection = result.checkpoint.protection,
                    auditAuthorizationReady = result.authorizationReady,
                    assessment = result.assessment,
                    emergencyStatus = result.emergencyStatus,
                    errorMessage = result.error?.let {
                        it.message ?: it::class.java.simpleName
                    },
                )
            }.onFailure { error ->
                if (error is CancellationException) throw error
                if (refreshGeneration.get() != generation) return@onFailure
                val sealedRecoveryModuleIds = runCatching {
                    JSONObject(getModuleAuditRecoveryStatus())
                        .getJSONArray("failures")
                        .moduleIds()
                }.getOrDefault(emptyList())
                val emergencyStatus = runCatching {
                    parseModuleAuditResponseStatus(getModuleAuditResponseStatus()).emergency
                }.getOrNull() ?: initialResponseStatus?.emergency
                _uiState.update {
                    it.copy(
                        isLoading = false,
                        isRefreshing = false,
                        verificationModuleId = null,
                        recoverableModuleIds = sealedRecoveryModuleIds,
                        sealedRecoveryModuleIds = sealedRecoveryModuleIds,
                        checkpointCompromised = it.checkpointCompromised ||
                            sealedRecoveryModuleIds.isNotEmpty(),
                        recoverySafeMode = recoverySafeMode,
                        emergencyStatus = emergencyStatus,
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
        val assessment: AuditAssessment?,
        val sealedRecoveryModuleIds: List<String>,
        val emergencyStatus: AuditEmergencyStatus?,
        val storeRevision: String,
        val error: Throwable?,
    )

    private suspend fun ensureAuditAuthorization(
        prefetchedStatus: JSONObject? = null,
        kernelSafeMode: Boolean = _uiState.value.recoverySafeMode,
    ): Boolean {
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

        if (kernelSafeMode) {
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

    private suspend fun createAuthorization(
        action: String,
        moduleId: String? = null,
        incidentId: String? = null,
    ): String =
        checkpointStore.signAuditAuthorization(
            getModuleAuditAuthorizationChallenge(action, moduleId, incidentId)
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
            if (!state.recoverySafeMode) {
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
                withAuditMutationSession { _, receipts ->
                    recoverSealedHistories(
                        _uiState.value.sealedRecoveryModuleIds,
                        receipts = receipts,
                    )
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
                withAuditMutationSession { _, receipts ->
                    receipts.record(
                        runInstalledModuleRescan(createAuthorization("rescan")),
                        "rescan",
                    )
                }
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
                withAuditMutationSession { _, receipts ->
                    receipts.record(
                        pruneStaleModuleAuditHistories(createAuthorization("prune")),
                        "prune",
                    )
                }
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
        val module = _uiState.value.assessment?.module(moduleId)
        if (
            module?.disposition !in setOf(
                AuditModuleDisposition.SecureRemovalRequired,
                AuditModuleDisposition.SealedRecoveryRequired,
            ) || module?.secureRemovalRoute?.available != true
        ) {
            return
        }
        viewModelScope.launch {
            runCatching {
                withContext(Dispatchers.IO) {
                    withAuditMutationSession { _, _ ->
                        containModuleForSecureRemoval(moduleId)
                    }
                }
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
            val assessmentRecoveryIds = state.assessment?.sealedRecoveryModuleIds.orEmpty()
            if (!state.canSecurelyRemove(moduleId)) {
                _uiState.update {
                    it.copy(
                        errorMessage = ksuApp.getString(
                            R.string.security_audit_secure_remove_unavailable
                        ),
                    )
                }
                return
            }
            sealedRecoveryModuleIds = if (
                moduleId in assessmentRecoveryIds
            ) {
                assessmentRecoveryIds
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
                withAuditMutationSession { installSession, receipts ->
                    if (sealedRecoveryModuleIds.isNotEmpty()) {
                        recoverSealedHistories(
                            sealedRecoveryModuleIds,
                            trackSecureRemoval = true,
                            receipts = receipts,
                            nextAuthorizationSession = installSession,
                        )
                    }
                    _uiState.update { it.copy(secureRemovalPhase = SecureRemovalPhase.RemovingModule) }
                    receipts.record(
                        runSecureModuleRemoval(
                            moduleId,
                            createAuthorization("secure-remove", moduleId),
                        ),
                        "secure-remove",
                        moduleId,
                    )
                    _uiState.update { it.copy(secureRemovalPhase = SecureRemovalPhase.RefreshingModules) }
                }
            }
            result.onSuccess {
                _uiState.update { it.copy(secureRemovalPhase = SecureRemovalPhase.Completed) }
            }.onFailure { error ->
                if (error is CancellationException) throw error
                val postCommitFailure = error as? AuditPostCommitFailure
                val secureRemovalCommitted = postCommitFailure
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
            _uiState.value.auditMutationBlocked ||
            _uiState.value.closingIncidentId != null
        ) return
        _uiState.update { it.copy(closingIncidentId = incidentId, errorMessage = null) }
        viewModelScope.launch(Dispatchers.IO) {
            runCatching {
                withAuditMutationSession { _, receipts ->
                    receipts.record(
                        closeModuleAuditIncident(
                            moduleId,
                            incidentId,
                            createAuthorization("close-incident", moduleId, incidentId),
                        ),
                        "close-incident",
                        moduleId,
                    )
                }
            }.onFailure { error ->
                if (error is CancellationException) throw error
                _uiState.update {
                    it.copy(errorMessage = error.message ?: error::class.java.simpleName)
                }
            }
            _uiState.update { it.copy(closingIncidentId = null) }
            refresh()
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
            } != false ||
            _uiState.value.auditMutationBlocked ||
            _uiState.value.deletingScriptEntryId != null
        ) return
        _uiState.update { it.copy(deletingScriptEntryId = entryId, errorMessage = null) }
        viewModelScope.launch(Dispatchers.IO) {
            runCatching {
                withAuditMutationSession { _, receipts ->
                    receipts.record(
                        deleteQuarantinedAuditScript(
                            entryId,
                            createAuthorization(
                                action = "delete-quarantined-script",
                                incidentId = entryId,
                            ),
                        ),
                        "delete-quarantined-script",
                        entryId,
                    )
                }
            }.onFailure { error ->
                if (error is CancellationException) throw error
                _uiState.update {
                    it.copy(errorMessage = error.message ?: error::class.java.simpleName)
                }
            }
            _uiState.update { it.copy(deletingScriptEntryId = null) }
            refresh()
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
            } != false ||
            _uiState.value.auditMutationBlocked ||
            _uiState.value.retryingScriptEntryId != null
        ) return
        _uiState.update { it.copy(retryingScriptEntryId = entryId, errorMessage = null) }
        viewModelScope.launch(Dispatchers.IO) {
            runCatching {
                withAuditMutationSession { _, receipts ->
                    receipts.record(
                        retryQuarantinedAuditScriptContainment(
                            entryId,
                            createAuthorization(
                                action = "retry-script-containment",
                                incidentId = entryId,
                            ),
                        ),
                        "retry-script-containment",
                        entryId,
                    )
                }
            }.onFailure { error ->
                if (error is CancellationException) throw error
                _uiState.update {
                    it.copy(errorMessage = error.message ?: error::class.java.simpleName)
                }
            }
            _uiState.update { it.copy(retryingScriptEntryId = null) }
            refresh()
        }
    }

    private suspend fun recoverSealedHistories(
        moduleIds: List<String>,
        trackSecureRemoval: Boolean = false,
        receipts: MutableCollection<AuditTransactionReceipt>,
        nextAuthorizationSession: String? = null,
    ) {
        if (trackSecureRemoval) {
            _uiState.update { it.copy(secureRemovalPhase = SecureRemovalPhase.RecoveringAudit) }
        }
        ensureAuditAuthorization()
        for (moduleId in moduleIds) {
            val challenge = getModuleAuditAuthorizationChallenge("recover-sealed", moduleId)
            val authorization = checkpointStore.signSealedRecoveryAuthorization(challenge)
            receipts.record(
                recoverManagerSealedAudit(moduleId, authorization),
                "recover-sealed",
                moduleId,
            )
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
        if (nextAuthorizationSession != null) {
            // Committing the recovery seal consumes its pending HMAC key. A
            // following transaction must be authorized against the resulting
            // rotated inventory, so establish that seal before continuing.
            sealModuleAuditSession(nextAuthorizationSession, checkpointStore)
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
