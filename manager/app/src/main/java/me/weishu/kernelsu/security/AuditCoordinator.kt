package me.weishu.kernelsu.security

import android.content.Context
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import me.weishu.kernelsu.R
import me.weishu.kernelsu.ui.util.beginAuditInstallSession
import me.weishu.kernelsu.ui.util.closeModuleAuditIncident
import me.weishu.kernelsu.ui.util.commitModuleAuditSeal
import me.weishu.kernelsu.ui.util.containModuleForSecureRemoval
import me.weishu.kernelsu.ui.util.deleteQuarantinedAuditScript
import me.weishu.kernelsu.ui.util.getModuleAuditAuthorizationChallenge
import me.weishu.kernelsu.ui.util.getModuleAuditAuthorizationStatus
import me.weishu.kernelsu.ui.util.getModuleAuditCheckpoint
import me.weishu.kernelsu.ui.util.getModuleAuditHistories
import me.weishu.kernelsu.ui.util.getModuleAuditSealStatus
import me.weishu.kernelsu.ui.util.pruneStaleModuleAuditHistories
import me.weishu.kernelsu.ui.util.reconcileModuleAuditResponse
import me.weishu.kernelsu.ui.util.recoverManagerSealedAudit
import me.weishu.kernelsu.ui.util.registerModuleAuditAuthorizationKey
import me.weishu.kernelsu.ui.util.releaseAuditInstallSession
import me.weishu.kernelsu.ui.util.rescanInstalledModules
import me.weishu.kernelsu.ui.util.retryQuarantinedAuditScriptContainment
import me.weishu.kernelsu.ui.util.securelyRemoveModule
import me.weishu.kernelsu.ui.util.streamModuleAuditDashboard
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.atomic.AtomicLong

enum class AuditSnapshotPolicy {
    ReuseVerified,
    Revalidate,
}

enum class AuditCoordinatorStage {
    WaitingForLock,
    VerifyingHistories,
    VerifyingCheckpoint,
    Authorizing,
    Executing,
    Sealing,
    Reconciling,
}

data class AuditCoordinatorProgress(
    val stage: AuditCoordinatorStage,
    val action: String? = null,
    val moduleId: String? = null,
    val completed: Int = 0,
    val total: Int = 0,
)

data class ManagerAuditSnapshot(
    val rawHistories: String,
    val checkpoint: AuditCheckpointVerification,
    val initialized: Boolean,
    val authorizationReady: Boolean,
    val assessment: AuditAssessment?,
    val kernelSafeMode: Boolean,
    val emergencyStatus: AuditEmergencyStatus?,
    val storeRevision: String,
    val synchronizationError: Throwable? = null,
)

data class ModuleAuditInstallTrust(
    val releasableModuleIds: Set<String>,
)

enum class SecureRemovalStage {
    RecoveringAudit,
    AnchoringAudit,
    RemovingModule,
    RefreshingModules,
}

class AuditPostCommitFailure internal constructor(
    val receipts: List<AuditTransactionReceipt>,
    cause: Throwable,
) : IllegalStateException(
    "Audit transaction ${receipts.joinToString { it.operationId }} committed, " +
        "but Manager synchronization failed: " +
        (cause.message ?: cause::class.java.simpleName),
    cause,
)

class AuditInstallationSession internal constructor(
    private val sealOperation: suspend () -> ModuleAuditInstallTrust,
) {
    suspend fun seal(): ModuleAuditInstallTrust = sealOperation()
}

/**
 * The sole owner of Manager-side audit trust state.
 *
 * ksud and the signed on-disk audit store remain authoritative. This class
 * serializes Manager verification, checkpoint reconciliation, authorization,
 * sealing, and composite audit workflows around one checkpoint store instance.
 */
class AuditCoordinator internal constructor(context: Context) {
    private data class SealSynchronization(val committed: Boolean)

    private data class CachedSnapshot(
        val epoch: Long,
        val value: ManagerAuditSnapshot,
    )

    private val appContext = context.applicationContext
    private val checkpointStore = ModuleAuditCheckpointStore(appContext)
    private val operationMutex = Mutex()
    private val invalidationEpoch = AtomicLong()

    @Volatile
    private var cachedSnapshot: CachedSnapshot? = null

    private val mutableLatestSnapshot = MutableStateFlow<ManagerAuditSnapshot?>(null)
    val latestSnapshot = mutableLatestSnapshot.asStateFlow()

    private val mutableProgress = MutableStateFlow<AuditCoordinatorProgress?>(null)
    val progress = mutableProgress.asStateFlow()

    private val mutableCommits = MutableSharedFlow<AuditTransactionReceipt>(
        extraBufferCapacity = 16,
    )
    val commits = mutableCommits.asSharedFlow()

    fun invalidate() {
        invalidationEpoch.incrementAndGet()
    }

    suspend fun cachedDashboard(): AuditDashboardCache? =
        operationMutex.withLock { checkpointStore.readDashboardCache() }

    suspend fun snapshot(
        policy: AuditSnapshotPolicy = AuditSnapshotPolicy.ReuseVerified,
    ): ManagerAuditSnapshot {
        val requestedEpoch = when (policy) {
            AuditSnapshotPolicy.ReuseVerified -> invalidationEpoch.get()
            AuditSnapshotPolicy.Revalidate -> invalidationEpoch.incrementAndGet()
        }
        mutableProgress.value = AuditCoordinatorProgress(
            stage = AuditCoordinatorStage.WaitingForLock,
            action = "verify",
        )
        return try {
            operationMutex.withLock {
                cachedSnapshot
                    ?.takeIf { it.epoch >= requestedEpoch }
                    ?.value
                    ?: verifySnapshotUnlocked(installSession = null)
            }
        } finally {
            mutableProgress.value = null
        }
    }

    suspend fun <T> withInstallationSession(
        block: suspend AuditInstallationSession.() -> T,
    ): T {
        mutableProgress.value = AuditCoordinatorProgress(
            stage = AuditCoordinatorStage.WaitingForLock,
            action = "install",
        )
        return try {
            operationMutex.withLock {
                val sessionId = beginAuditInstallSession()
                var primaryFailure: Throwable? = null
                var sealCount = 0
                try {
                    val session = AuditInstallationSession {
                        invalidate()
                        val verified = verifySnapshotUnlocked(sessionId)
                        sealCount += 1
                        requireInstallTrust(verified)
                    }
                    session.block().also {
                        if (sealCount < 2) invalidate()
                    }
                } catch (error: Throwable) {
                    primaryFailure = error
                    invalidate()
                    throw error
                } finally {
                    runCatching {
                        withContext(NonCancellable) {
                            releaseAuditInstallSession(sessionId)
                        }
                    }.onFailure { releaseError ->
                        primaryFailure?.addSuppressed(releaseError) ?: throw releaseError
                    }
                }
            }
        } finally {
            mutableProgress.value = null
        }
    }

    suspend fun recoverCheckpoint() {
        withMutationSession("recover-sealed") { sessionId, receipts ->
            val snapshot = snapshotForMutationUnlocked(sessionId)
            val assessment = checkNotNull(snapshot.assessment) {
                "Verified audit assessment is unavailable"
            }
            check(assessment.kernelSafeMode) {
                appContext.getString(R.string.security_audit_recovery_safe_mode)
            }
            val moduleIds = assessment.sealedRecoveryModuleIds
            check(moduleIds.isNotEmpty()) { "No Manager-sealed audit history requires recovery" }
            recoverSealedHistoriesUnlocked(
                sessionId,
                moduleIds,
                receipts,
                kernelSafeMode = assessment.kernelSafeMode,
                anchorForNextAction = false,
            )
        }
    }

    suspend fun rescan() {
        withMutationSession("rescan") { sessionId, receipts ->
            val authorization = createAuthorizationUnlocked(sessionId, "rescan")
            receipts.record(rescanInstalledModules(authorization), "rescan")
        }
    }

    suspend fun prune() {
        withMutationSession("prune") { sessionId, receipts ->
            val snapshot = snapshotForMutationUnlocked(sessionId)
            check(snapshot.assessment?.staleModuleIds?.isNotEmpty() == true) {
                "No stale module audit history is available"
            }
            val authorization = createAuthorizationUnlocked(sessionId, "prune")
            receipts.record(pruneStaleModuleAuditHistories(authorization), "prune")
        }
    }

    suspend fun containForSecureRemoval(moduleId: String) {
        withMutationSession("contain", synchronizeResponse = false) { sessionId, _ ->
            val module = checkNotNull(
                snapshotForMutationUnlocked(sessionId).assessment?.module(moduleId)
            ) { "Module is not present in the verified audit assessment" }
            check(
                module.disposition == AuditModuleDisposition.SecureRemovalRequired ||
                    module.disposition == AuditModuleDisposition.SealedRecoveryRequired
            ) { "Module is not eligible for secure removal containment" }
            check(module.secureRemovalRoute?.available == true) {
                "Secure removal containment prerequisites are not satisfied"
            }
            containModuleForSecureRemoval(moduleId)
        }
    }

    suspend fun securelyRemove(
        moduleId: String,
        onStage: (SecureRemovalStage) -> Unit = {},
    ) {
        withMutationSession("secure-remove") { sessionId, receipts ->
            val snapshot = snapshotForMutationUnlocked(sessionId)
            val assessment = checkNotNull(snapshot.assessment) {
                "Verified audit assessment is unavailable"
            }
            val module = assessment.module(moduleId)
            check(module?.secureRemovalRoute?.available == true) {
                "Module is not eligible for secure removal"
            }
            val recoveryIds = if (moduleId in assessment.sealedRecoveryModuleIds) {
                assessment.sealedRecoveryModuleIds
            } else {
                emptyList()
            }
            if (recoveryIds.isNotEmpty()) {
                onStage(SecureRemovalStage.RecoveringAudit)
                recoverSealedHistoriesUnlocked(
                    sessionId,
                    recoveryIds,
                    receipts,
                    kernelSafeMode = assessment.kernelSafeMode,
                    anchorForNextAction = true,
                    onAnchoring = { onStage(SecureRemovalStage.AnchoringAudit) },
                )
            }
            onStage(SecureRemovalStage.RemovingModule)
            val authorization = createAuthorizationUnlocked(
                sessionId,
                action = "secure-remove",
                moduleId = moduleId,
            )
            receipts.record(
                securelyRemoveModule(moduleId, authorization),
                "secure-remove",
                moduleId,
            )
            onStage(SecureRemovalStage.RefreshingModules)
        }
    }

    suspend fun closeIncident(moduleId: String, incidentId: String) {
        withMutationSession("close-incident") { sessionId, receipts ->
            val incident = checkNotNull(
                findIncident(
                    snapshotForMutationUnlocked(sessionId).rawHistories,
                    moduleId,
                    incidentId,
                )
            ) { "Audit incident is not present in the verified snapshot" }
            check(incident.optString("state") == "resolved") {
                "Only a resolved audit incident can be closed"
            }
            check(incident.hasReadyRoute("close_incident")) {
                "Audit incident close prerequisites are not satisfied"
            }
            val authorization = createAuthorizationUnlocked(
                sessionId,
                action = "close-incident",
                moduleId = moduleId,
                incidentId = incidentId,
            )
            receipts.record(
                closeModuleAuditIncident(moduleId, incidentId, authorization),
                "close-incident",
                moduleId,
            )
        }
    }

    suspend fun deleteQuarantinedScript(entryId: String) {
        withMutationSession("delete-quarantined-script") { sessionId, receipts ->
            val entry = snapshotForMutationUnlocked(sessionId).emergencyStatus
                .scriptEntry(entryId)
            check(entry?.recoveryRoutes?.any {
                it.action == "delete_quarantined_script" && it.ready
            } == true) { "Quarantined script deletion prerequisites are not satisfied" }
            val authorization = createAuthorizationUnlocked(
                sessionId,
                action = "delete-quarantined-script",
                incidentId = entryId,
            )
            receipts.record(
                deleteQuarantinedAuditScript(entryId, authorization),
                "delete-quarantined-script",
                entryId,
            )
        }
    }

    suspend fun retryScriptContainment(entryId: String) {
        withMutationSession("retry-script-containment") { sessionId, receipts ->
            val entry = snapshotForMutationUnlocked(sessionId).emergencyStatus
                .scriptEntry(entryId)
            check(entry?.recoveryRoutes?.any {
                it.action == "retry_script_containment" && it.ready
            } == true) { "Script containment retry prerequisites are not satisfied" }
            val authorization = createAuthorizationUnlocked(
                sessionId,
                action = "retry-script-containment",
                incidentId = entryId,
            )
            receipts.record(
                retryQuarantinedAuditScriptContainment(entryId, authorization),
                "retry-script-containment",
                entryId,
            )
        }
    }

    private suspend fun <T> withMutationSession(
        action: String,
        synchronizeResponse: Boolean = true,
        block: suspend (String, MutableCollection<AuditTransactionReceipt>) -> T,
    ): T {
        mutableProgress.value = AuditCoordinatorProgress(
            stage = AuditCoordinatorStage.WaitingForLock,
            action = action,
        )
        return try {
            operationMutex.withLock {
                val sessionId = beginAuditInstallSession(timeoutSeconds = 600)
                val receipts = mutableListOf<AuditTransactionReceipt>()
                var primaryFailure: Throwable? = null
                try {
                    mutableProgress.value = AuditCoordinatorProgress(
                        stage = AuditCoordinatorStage.Executing,
                        action = action,
                    )
                    val result = block(sessionId, receipts)
                    invalidate()
                    verifySnapshotUnlocked(sessionId)
                    if (synchronizeResponse) {
                        mutableProgress.value = AuditCoordinatorProgress(
                            stage = AuditCoordinatorStage.Reconciling,
                            action = action,
                        )
                        reconcileModuleAuditResponse()
                        invalidate()
                        verifySnapshotUnlocked(sessionId)
                    }
                    result
                } catch (error: Throwable) {
                    val propagated = if (error is CancellationException || receipts.isEmpty()) {
                        error
                    } else {
                        AuditPostCommitFailure(receipts.toList(), error)
                    }
                    primaryFailure = propagated
                    throw propagated
                } finally {
                    var finalizationFailure: Throwable? = null
                    withContext(NonCancellable) {
                        runCatching { releaseAuditInstallSession(sessionId) }
                            .onFailure { finalizationFailure = it }
                        receipts.distinctBy(AuditTransactionReceipt::operationId).forEach { receipt ->
                            runCatching { mutableCommits.emit(receipt) }
                                .onFailure { publishFailure ->
                                    finalizationFailure?.addSuppressed(publishFailure)
                                        ?: run { finalizationFailure = publishFailure }
                                }
                        }
                    }
                    finalizationFailure?.let { error ->
                        val failure = primaryFailure
                        if (failure == null) {
                            throw if (receipts.isEmpty()) {
                                error
                            } else {
                                AuditPostCommitFailure(receipts.toList(), error)
                            }
                        }
                        failure.addSuppressed(error)
                    }
                }
            }
        } finally {
            mutableProgress.value = null
        }
    }

    private suspend fun snapshotForMutationUnlocked(sessionId: String): ManagerAuditSnapshot {
        val epoch = invalidationEpoch.get()
        return cachedSnapshot
            ?.takeIf { it.epoch >= epoch }
            ?.value
            ?: verifySnapshotUnlocked(sessionId)
    }

    private suspend fun verifySnapshotUnlocked(
        installSession: String?,
        sealPass: Int = 0,
    ): ManagerAuditSnapshot {
        mutableProgress.value = AuditCoordinatorProgress(
            stage = AuditCoordinatorStage.VerifyingHistories,
            action = if (installSession == null) "verify" else "seal-session",
        )
        val verificationEpoch = invalidationEpoch.get()
        val histories = linkedMapOf<String, JSONObject>()
        var completion: JSONObject? = null
        streamModuleAuditDashboard(installSession) { rawLine ->
            val line = JSONObject(rawLine)
            when (line.getString("type")) {
                "start" -> {
                    histories.clear()
                    mutableProgress.value = AuditCoordinatorProgress(
                        stage = AuditCoordinatorStage.VerifyingHistories,
                        completed = 0,
                        total = line.getInt("total_modules"),
                    )
                }
                "progress" -> {
                    val stage = if (line.optString("phase") == "checkpoint") {
                        AuditCoordinatorStage.VerifyingCheckpoint
                    } else {
                        AuditCoordinatorStage.VerifyingHistories
                    }
                    mutableProgress.value = AuditCoordinatorProgress(
                        stage = stage,
                        moduleId = line.optString("module_id").takeIf(String::isNotBlank),
                        completed = line.getInt("completed"),
                        total = line.getInt("total_modules"),
                    )
                }
                "module" -> histories[line.getString("module_id")] = line.getJSONObject("history")
                "error" -> error(line.optString("error", "Module audit verification failed"))
                "complete" -> completion = line
            }
        }

        val completed = checkNotNull(completion) { "ksud dashboard verification did not complete" }
        val rawHistories = JSONArray(histories.values).toString()
        val responseStatus = parseModuleAuditResponseStatus(
            completed.getJSONObject("response_status").toString()
        )
        if (completed.optBoolean("uninitialized", false)) {
            val unavailable = ManagerAuditSnapshot(
                rawHistories = "[]",
                checkpoint = checkpointStore.checkpointUnavailable(
                    "Module audit history is not initialized"
                ),
                initialized = false,
                authorizationReady = false,
                assessment = null,
                kernelSafeMode = responseStatus.kernelSafeMode,
                emergencyStatus = responseStatus.emergency,
                storeRevision = completed.getString("store_revision"),
            )
            rememberSnapshot(verificationEpoch, unavailable)
            return unavailable
        }

        val assessment = parseAuditAssessment(completed.getJSONObject("assessment"))
        check(assessment.snapshotRevision == completed.getString("store_revision")) {
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
        check(assessment.kernelSafeMode == responseStatus.kernelSafeMode) {
            "Audit assessment safe-mode state does not match its response snapshot"
        }
        val rawCheckpoint = completed.getJSONObject("checkpoint")
        check(assessment.inventoryHash == rawCheckpoint.getString("inventory_hash")) {
            "Audit assessment inventory does not match its checkpoint"
        }
        val checkpointDegraded = completed.optBoolean("checkpoint_degraded", false)
        check(
            checkpointDegraded ==
                (assessment.inventoryRelation == AuditInventoryRelation.SealedDamage)
        ) { "Audit snapshot relation does not match its integrity state" }

        val sealStatus = completed.getJSONObject("seal_status")
        val authorizationStatus = completed.getJSONObject("authorization_status")
        check(
            assessment.authorizationConfigured ==
                authorizationStatus.optBoolean("configured", false)
        ) { "Audit assessment authorization state does not match its snapshot" }
        var checkpoint = checkpointStore.reconcile(
            rawCheckpoint.toString(),
            rawHistories,
            sealStatus.nullableString("seal_hash"),
        )
        if (checkpointDegraded && checkpoint.trust != AuditCheckpointTrust.Compromised) {
            val recoverableModules = completed.getJSONArray("integrity_failures").moduleIds()
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
        check(
            assessment.sealedRecoveryModuleIds.toSet() == checkpoint.recoverableModules.toSet()
        ) { "Audit assessment recovery set does not match the verified checkpoint" }

        val authorizationResult = if (
            checkpoint.trust == AuditCheckpointTrust.Initialized ||
            checkpoint.trust == AuditCheckpointTrust.Verified
        ) {
            runCatching {
                ensureAuthorizationUnlocked(
                    authorizationStatus,
                    assessment.kernelSafeMode,
                )
            }
        } else {
            Result.success(false)
        }
        authorizationResult.exceptionOrNull()?.let {
            if (it is CancellationException) throw it
        }
        val sealResult = authorizationResult.mapCatching { ready ->
            if (ready) ensureSealUnlocked(sealStatus) else SealSynchronization(committed = false)
        }
        sealResult.exceptionOrNull()?.let { error ->
            if (error is CancellationException) throw error
            checkpoint = checkpointStore.externalIntegrityFailure(
                error.message ?: error::class.java.simpleName
            )
        }
        if (sealResult.getOrNull()?.committed == true) {
            check(sealPass < 3) { "Manager audit seal did not converge to a stable snapshot" }
            invalidate()
            return verifySnapshotUnlocked(installSession, sealPass + 1)
        }
        val authorizationReady = authorizationResult.getOrDefault(false) && sealResult.isSuccess
        if (authorizationReady && checkpoint.trust != AuditCheckpointTrust.Compromised) {
            checkpointStore.writeDashboardCache(
                JSONObject()
                    .put("histories", JSONArray(rawHistories))
                    .put("stale_module_ids", JSONArray(assessment.staleModuleIds))
                    .put("key_protection", checkpoint.protection.wireName)
                    .toString()
            )
        }
        val verified = ManagerAuditSnapshot(
            rawHistories = rawHistories,
            checkpoint = checkpoint,
            initialized = true,
            authorizationReady = authorizationReady,
            assessment = assessment,
            kernelSafeMode = assessment.kernelSafeMode,
            emergencyStatus = responseStatus.emergency,
            storeRevision = completed.getString("store_revision"),
            synchronizationError = sealResult.exceptionOrNull()
                ?: authorizationResult.exceptionOrNull(),
        )
        rememberSnapshot(verificationEpoch, verified)
        return verified
    }

    private fun rememberSnapshot(epoch: Long, snapshot: ManagerAuditSnapshot) {
        mutableLatestSnapshot.value = snapshot
        if (invalidationEpoch.get() == epoch) {
            cachedSnapshot = CachedSnapshot(epoch, snapshot)
        }
    }

    private suspend fun ensureAuthorizationUnlocked(
        prefetchedStatus: JSONObject? = null,
        kernelSafeMode: Boolean,
    ): Boolean {
        mutableProgress.value = AuditCoordinatorProgress(
            stage = AuditCoordinatorStage.Authorizing,
        )
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
                appContext.getString(R.string.security_audit_authorization_unavailable),
                cause,
            )
        }
        error(appContext.getString(R.string.security_audit_authorization_changed))
    }

    private suspend fun ensureSealUnlocked(
        prefetchedStatus: JSONObject? = null,
    ): SealSynchronization {
        mutableProgress.value = AuditCoordinatorProgress(
            stage = AuditCoordinatorStage.Sealing,
        )
        val status = prefetchedStatus ?: JSONObject(getModuleAuditSealStatus())
        val configured = status.optBoolean("configured", false)
        val sealedHash = status.nullableString("seal_hash")
        val currentHash = checkpointStore.currentSealHash()
        if (!requiresAuditSealCommit(
                configured,
                sealedHash,
                currentHash,
                checkpointStore.acceptablePreviousSealHash(),
            )
        ) {
            checkpointStore.markSealSynchronized(currentHash)
            return SealSynchronization(committed = false)
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
        return SealSynchronization(committed = true)
    }

    private suspend fun createAuthorizationUnlocked(
        sessionId: String,
        action: String,
        moduleId: String? = null,
        incidentId: String? = null,
    ): String {
        suspend fun challenge(): String =
            getModuleAuditAuthorizationChallenge(action, moduleId, incidentId)
        return try {
            checkpointStore.signAuditAuthorization(challenge())
        } catch (error: AuditInventoryChangedBeforeAuthorization) {
            invalidate()
            verifySnapshotUnlocked(sessionId)
            checkpointStore.signAuditAuthorization(challenge())
        }
    }

    private suspend fun recoverSealedHistoriesUnlocked(
        sessionId: String,
        moduleIds: List<String>,
        receipts: MutableCollection<AuditTransactionReceipt>,
        kernelSafeMode: Boolean,
        anchorForNextAction: Boolean,
        onAnchoring: () -> Unit = {},
    ) {
        ensureAuthorizationUnlocked(kernelSafeMode = kernelSafeMode)
        for (moduleId in moduleIds) {
            val challenge = getModuleAuditAuthorizationChallenge("recover-sealed", moduleId)
            val authorization = checkpointStore.signSealedRecoveryAuthorization(challenge)
            receipts.record(
                recoverManagerSealedAudit(moduleId, authorization),
                "recover-sealed",
                moduleId,
            )
            invalidate()
        }
        onAnchoring()
        val recovery = checkpointStore.acceptRecoveredChain(
            getModuleAuditCheckpoint(),
            getModuleAuditHistories(),
        )
        check(recovery.trust == AuditCheckpointTrust.Verified) {
            recovery.detail ?: "Unable to accept rebuilt audit chain"
        }
        check(ensureAuthorizationUnlocked(kernelSafeMode = kernelSafeMode)) {
            "Manager audit authorization is unavailable after recovery"
        }
        ensureSealUnlocked()
        if (anchorForNextAction) {
            invalidate()
            verifySnapshotUnlocked(sessionId)
        }
    }

    private fun requireInstallTrust(snapshot: ManagerAuditSnapshot): ModuleAuditInstallTrust {
        check(snapshot.initialized) {
            "Module audit store remained uninitialized after installation"
        }
        val assessment = checkNotNull(snapshot.assessment)
        check(assessment.inventoryRelation != AuditInventoryRelation.SealedDamage) {
            "Module audit installation session produced sealed inventory damage"
        }
        check(snapshot.checkpoint.recoverableModules.isEmpty()) {
            "Installed module audit transition requires explicit recovery"
        }
        val histories = JSONArray(snapshot.rawHistories)
        return ModuleAuditInstallTrust(
            releasableModuleIds = buildSet {
                for (index in 0 until histories.length()) {
                    val status = histories.getJSONObject(index).getJSONObject("status")
                    if (
                        !status.optBoolean("unresolved_risk", true) &&
                        status.nullableString("containment_state") == null
                    ) {
                        add(status.getString("module_id"))
                    }
                }
            }
        )
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
        invalidate()
    }

    private fun findIncident(
        rawHistories: String,
        moduleId: String,
        incidentId: String,
    ): JSONObject? {
        val histories = JSONArray(rawHistories)
        for (historyIndex in 0 until histories.length()) {
            val status = histories.getJSONObject(historyIndex).getJSONObject("status")
            if (status.optString("module_id") != moduleId) continue
            val incidents = status.optJSONArray("incidents") ?: return null
            for (incidentIndex in 0 until incidents.length()) {
                val incident = incidents.getJSONObject(incidentIndex)
                if (incident.optString("incident_id") == incidentId) return incident
            }
        }
        return null
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

private fun JSONObject.nullableString(name: String): String? =
    if (!has(name) || isNull(name)) null else optString(name).takeIf(String::isNotBlank)

private fun JSONObject.hasReadyRoute(action: String): Boolean {
    val routes = optJSONArray("recovery_routes") ?: return false
    for (index in 0 until routes.length()) {
        val route = routes.getJSONObject(index)
        if (route.optString("action") == action && route.optBoolean("ready", false)) return true
    }
    return false
}

private fun AuditEmergencyStatus?.scriptEntry(entryId: String) =
    this?.scriptQuarantines
        ?.asSequence()
        ?.flatMap { it.entries.asSequence() }
        ?.firstOrNull { it.entryId == entryId }
