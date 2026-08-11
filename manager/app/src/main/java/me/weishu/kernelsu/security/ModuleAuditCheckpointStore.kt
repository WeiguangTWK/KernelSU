package me.weishu.kernelsu.security

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.KeyPairGenerator
import java.security.KeyFactory
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec

enum class AuditCheckpointTrust(val wireName: String) {
    NotConfigured("not_configured"),
    Initialized("keystore_initialized"),
    Verified("keystore_verified"),
    Compromised("keystore_compromised"),
}

enum class AuditKeyProtection(val wireName: String) {
    Hardware("hardware"),
    Degraded("degraded"),
    Emergency("emergency"),
    Unavailable("unavailable"),
}

data class AuditCheckpointVerification(
    val trust: AuditCheckpointTrust,
    val detail: String? = null,
    val protection: AuditKeyProtection = AuditKeyProtection.Unavailable,
    val recoverableModules: List<String> = emptyList(),
)

internal fun validateAuditKeyProtectionTransition(
    recorded: AuditKeyProtection?,
    current: AuditKeyProtection,
) {
    if (
        recorded == null ||
        recorded == current ||
        (recorded == AuditKeyProtection.Degraded && current == AuditKeyProtection.Hardware)
    ) {
        return
    }
    error(
        if (recorded == AuditKeyProtection.Hardware) {
            "Manager checkpoint hardware protection was downgraded"
        } else {
            "Manager checkpoint key protection changed unexpectedly"
        }
    )
}

internal fun requiresAuditSealCommit(
    configured: Boolean,
    sealedHash: String?,
    currentHash: String,
    previousHash: String?,
): Boolean {
    if (configured && sealedHash == currentHash) return false
    if (configured) {
        check(sealedHash == previousHash) {
            "Manager audit seal disappeared, changed, or rolled back"
        }
    } else {
        check(previousHash == null || previousHash == currentHash) {
            "Manager audit seal is missing during an unsealed checkpoint transition"
        }
    }
    return true
}

internal fun selectAuditTransitionBaseHash(
    sealedHash: String?,
    currentHash: String,
    previousHash: String?,
): String {
    if (previousHash == null || previousHash == currentHash) return currentHash
    return when (sealedHash) {
        currentHash -> currentHash
        null, previousHash -> previousHash
        else -> error("ksud seal does not match the recoverable Manager transition")
    }
}

internal fun isAuthenticatedAuditChainRebuild(
    previousHashes: List<String>,
    currentHashes: List<String>,
    currentHighRisk: Boolean,
    hmacVerified: Boolean,
    eventCount: Long,
    lastSequence: Long,
    lastPreviousHash: String,
    lastKind: String,
    corruptedFromSequence: Long,
    reason: String?,
    quarantine: String?,
): Boolean {
    if (!currentHighRisk || !hmacVerified) return false
    if (eventCount != currentHashes.size.toLong() || lastSequence != eventCount) return false
    if (lastKind != "integrity_incident" || reason.isNullOrBlank()) return false
    if (quarantine.isNullOrBlank()) return false
    val prefixLength = previousHashes
        .zip(currentHashes)
        .takeWhile { (oldHash, newHash) -> oldHash == newHash }
        .size
    if (prefixLength >= previousHashes.size) return false
    if (currentHashes.size != prefixLength + 1) return false
    val expectedSequence = prefixLength.toLong() + 1L
    if (corruptedFromSequence != 0L && corruptedFromSequence != expectedSequence) return false
    val expectedPreviousHash = if (prefixLength == 0) {
        AUDIT_GENESIS_HASH
    } else {
        previousHashes[prefixLength - 1]
    }
    return lastPreviousHash == expectedPreviousHash
}

private const val AUDIT_GENESIS_HASH =
    "0000000000000000000000000000000000000000000000000000000000000000"

class ModuleAuditCheckpointStore(context: Context) {
    private val checkpointFile = AtomicFile(File(context.noBackupFilesDir, CHECKPOINT_FILE_NAME))
    private val previousCheckpointFile =
        AtomicFile(File(context.noBackupFilesDir, PREVIOUS_CHECKPOINT_FILE_NAME))
    private val softwareKeyFile = AtomicFile(File(context.noBackupFilesDir, SOFTWARE_KEY_FILE_NAME))
    @Volatile
    private var trustedInventoryHash: String? = null
    @Volatile
    private var activeProtection = AuditKeyProtection.Unavailable
    @Volatile
    private var previousEnvelopeHash: String? = null
    @Volatile
    private var currentEnvelopeHash: String? = null
    @Volatile
    private var observedSealHash: String? = null

    fun reconcile(
        rawPayload: String,
        rawHistories: String? = null,
        sealedEnvelopeHash: String? = null,
    ): AuditCheckpointVerification =
        runCatching {
            observedSealHash = sealedEnvelopeHash
            val current = parsePayload(rawPayload)
            check(current.schemaVersion == CHECKPOINT_SCHEMA_VERSION) {
                "Unsupported current audit checkpoint payload schema"
            }
            check(current.inventoryHash.isSha256Hex()) {
                "Current audit checkpoint has no valid inventory hash"
            }
            val envelopeText = readEnvelope()
            val hasAndroidKey = runCatching {
                loadKeyStore().containsAlias(KEY_ALIAS)
            }.getOrDefault(false)
            val hasSoftwareKey = softwareKeyFile.baseFile.isFile

            when {
                envelopeText == null && !hasAndroidKey && !hasSoftwareKey -> {
                    check(current.operations.isEmpty()) {
                        "Manager checkpoint cannot be initialized over existing audit operations"
                    }
                    val signingKey = createBestAvailableSigningKey()
                    activeProtection = signingKey.protection
                    try {
                        persist(
                            rawPayload,
                            generation = 1L,
                            signingKey = signingKey,
                            previousEnvelope = null,
                        )
                    } catch (error: Throwable) {
                        discardSigningKey(signingKey.backend)
                        throw error
                    }
                    trustedInventoryHash = current.inventoryHash
                    previousEnvelopeHash = null
                    currentEnvelopeHash = readEnvelope()?.sha256Hex()
                    AuditCheckpointVerification(
                        AuditCheckpointTrust.Initialized,
                        protection = signingKey.protection,
                    )
                }

                envelopeText == null -> compromised("Manager checkpoint data is missing")
                else -> {
                    val envelope = parseEnvelope(envelopeText)
                    if (envelope.backend == AuditKeyBackend.SoftwareFile && hasAndroidKey) {
                        return@runCatching compromised(
                            "Manager checkpoint key backend changed while its Keystore key remains"
                        )
                    }
                    val signingKey = loadSigningKey(envelope.backend)
                    activeProtection = signingKey.protection
                    if (envelope.keyId != signingKey.publicKey.authorizationKeyId()) {
                        return@runCatching compromised("Manager checkpoint key identity changed")
                    }
                    validateAuditKeyProtectionTransition(
                        envelope.protection,
                        signingKey.protection,
                    )
                    if (!verifyEnvelope(envelope, signingKey.publicKey)) {
                        return@runCatching compromised("Manager checkpoint signature is invalid")
                    }
                    val (baseEnvelopeText, baseEnvelope) = transitionBase(
                        envelopeText,
                        envelope,
                        signingKey.publicKey,
                        sealedEnvelopeHash,
                    )
                    previousEnvelopeHash = baseEnvelopeText.sha256Hex()
                    val previous = parsePayload(baseEnvelope.payload)
                    val storedCurrent = parsePayload(envelope.payload)
                    val transition = analyzePayloadTransition(
                        previous,
                        current,
                        rawHistories?.let(::parseRecoveryEvidence).orEmpty(),
                        signingKey.publicKey,
                    )
                    transition.error?.let {
                        return@runCatching compromised(it, transition.recoverableModules)
                    }
                    if (
                        storedCurrent != current ||
                        envelope.schemaVersion != ENVELOPE_SCHEMA_VERSION ||
                        envelope.protection != signingKey.protection
                    ) {
                        persist(
                            rawPayload,
                            Math.addExact(baseEnvelope.generation, 1L),
                            signingKey,
                            baseEnvelopeText,
                        )
                    }
                    trustedInventoryHash = current.inventoryHash
                    currentEnvelopeHash = readEnvelope()?.sha256Hex()
                    AuditCheckpointVerification(
                        AuditCheckpointTrust.Verified,
                        protection = signingKey.protection,
                    )
                }
            }
        }.getOrElse { error ->
            trustedInventoryHash = null
            compromised(error.message ?: error::class.java.simpleName)
        }

    fun checkpointUnavailable(detail: String): AuditCheckpointVerification = runCatching {
        val hasEnvelope = checkpointFile.baseFile.isFile
        if (
            hasEnvelope ||
            runCatching { loadKeyStore().containsAlias(KEY_ALIAS) }.getOrDefault(false) ||
            softwareKeyFile.baseFile.isFile
        ) {
            compromised("Audit store unavailable after checkpoint: $detail")
        } else {
            AuditCheckpointVerification(AuditCheckpointTrust.NotConfigured, detail = detail)
        }
    }.getOrElse { compromised("Unable to inspect Manager checkpoint: ${it.message ?: detail}") }

    fun externalIntegrityFailure(detail: String): AuditCheckpointVerification = compromised(detail)

    fun acceptRecoveredChain(
        rawPayload: String,
        rawHistories: String,
    ): AuditCheckpointVerification = runCatching {
        val current = parsePayload(rawPayload)
        check(current.schemaVersion == CHECKPOINT_SCHEMA_VERSION) {
            "Unsupported current audit checkpoint payload schema"
        }
        check(current.inventoryHash.isSha256Hex()) {
            "Current audit checkpoint has no valid inventory hash"
        }
        val envelopeText = readEnvelope() ?: error("Manager checkpoint data is missing")
        val envelope = parseEnvelope(envelopeText)
        val hasAndroidKey = runCatching {
            loadKeyStore().containsAlias(KEY_ALIAS)
        }.getOrDefault(false)
        check(!(envelope.backend == AuditKeyBackend.SoftwareFile && hasAndroidKey)) {
            "Manager checkpoint key backend changed while its Keystore key remains"
        }
        val signingKey = loadSigningKey(envelope.backend)
        activeProtection = signingKey.protection
        check(envelope.keyId == signingKey.publicKey.authorizationKeyId()) {
            "Manager checkpoint key identity changed"
        }
        validateAuditKeyProtectionTransition(envelope.protection, signingKey.protection)
        check(verifyEnvelope(envelope, signingKey.publicKey)) {
            "Manager checkpoint signature is invalid"
        }
        val (baseEnvelopeText, baseEnvelope) = transitionBase(
            envelopeText,
            envelope,
            signingKey.publicKey,
            observedSealHash,
        )
        val previous = parsePayload(baseEnvelope.payload)
        val transition = analyzePayloadTransition(
            previous,
            current,
            parseRecoveryEvidence(rawHistories),
            signingKey.publicKey,
        )
        check(transition.recoverableModules.isNotEmpty()) {
            transition.error ?: "No authenticated chain rebuild is available"
        }

        persist(
            rawPayload,
            Math.addExact(baseEnvelope.generation, 1L),
            signingKey,
            baseEnvelopeText,
        )
        trustedInventoryHash = current.inventoryHash
        previousEnvelopeHash = baseEnvelopeText.sha256Hex()
        currentEnvelopeHash = readEnvelope()?.sha256Hex()
        AuditCheckpointVerification(
            trust = AuditCheckpointTrust.Verified,
            detail = "Accepted rebuilt audit chains: " +
                transition.recoverableModules.joinToString(),
            protection = signingKey.protection,
        )
    }.getOrElse { error ->
        compromised(error.message ?: error::class.java.simpleName)
    }

    private fun analyzePayloadTransition(
        previous: CheckpointPayload,
        current: CheckpointPayload,
        evidence: Map<String, RecoveryEvidence>,
        authorizationKey: PublicKey,
    ): PayloadTransition {
        if (previous.schemaVersion != current.schemaVersion) {
            return PayloadTransition("Audit checkpoint schema changed unexpectedly")
        }
        if (
            previous.hmacKeyId != current.hmacKeyId &&
            previous.nextHmacKeyId != current.hmacKeyId
        ) {
            return PayloadTransition("Audit HMAC key identity changed unexpectedly")
        }
        if (
            previous.hmacKeyId == current.hmacKeyId &&
            previous.nextHmacKeyId != current.nextHmacKeyId &&
            previous.modules == current.modules &&
            previous.tombstones == current.tombstones &&
            previous.operations == current.operations
        ) {
            return PayloadTransition("Pending audit HMAC key changed unexpectedly")
        }

        val currentTombstones = current.tombstones.toSet()
        val missingTombstones = previous.tombstones.filterNot(currentTombstones::contains)
        if (missingTombstones.isNotEmpty()) {
            return PayloadTransition(
                "Authenticated cleanup records disappeared: " +
                    missingTombstones.joinToString { it.moduleId }
            )
        }

        val currentOperations = current.operations.associateBy(CheckpointOperation::operationId)
        for (oldOperation in previous.operations) {
            val newOperation = currentOperations[oldOperation.operationId]
                ?: return PayloadTransition(
                    "Authenticated audit operation disappeared: ${oldOperation.operationId}"
                )
            if (
                oldOperation.action != newOperation.action ||
                oldOperation.baseInventoryHash != newOperation.baseInventoryHash ||
                oldOperation.argumentsHash != newOperation.argumentsHash ||
                oldOperation.authorizationHex != newOperation.authorizationHex ||
                oldOperation.targets != newOperation.targets
            ) {
                return PayloadTransition(
                    "Authenticated audit operation identity changed: ${oldOperation.operationId}"
                )
            }
            if (!newOperation.completedTargets.startsWith(oldOperation.completedTargets)) {
                return PayloadTransition(
                    "Authenticated audit operation progress rolled back: ${oldOperation.operationId}"
                )
            }
            if (oldOperation.state != "applying" && newOperation.state != oldOperation.state) {
                return PayloadTransition(
                    "Terminal audit operation changed state: ${oldOperation.operationId}"
                )
            }
            if (oldOperation.state != "applying" && newOperation.error != oldOperation.error) {
                return PayloadTransition(
                    "Terminal audit operation error changed: ${oldOperation.operationId}"
                )
            }
        }
        val previousOperationIds = previous.operations.mapTo(mutableSetOf()) { it.operationId }
        for (operation in current.operations) {
            if (
                operation.action !in setOf("rescan", "prune") ||
                operation.targets != operation.targets.sorted().distinct() ||
                operation.completedTargets != operation.completedTargets.sorted().distinct() ||
                !operation.targets.containsAll(operation.completedTargets) ||
                (operation.state == "interrupted") != (operation.error != null) ||
                (operation.error != null &&
                    (operation.error.isEmpty() || operation.error.length > 4096)) ||
                (operation.state == "applied" &&
                    operation.completedTargets != operation.targets)
            ) {
                return PayloadTransition(
                    "Authenticated audit operation is malformed: ${operation.operationId}"
                )
            }
            val isNew = operation.operationId !in previousOperationIds
            if (isNew && !verifyOperationAuthorization(operation, authorizationKey)) {
                return PayloadTransition(
                    "Audit operation has no valid Manager authorization: ${operation.operationId}"
                )
            }
            if (
                isNew &&
                operation.baseInventoryHash != previous.inventoryHash
            ) {
                return PayloadTransition(
                    "Audit operation is not bound to the previous checkpoint: ${operation.operationId}"
                )
            }
        }

        val currentModules = current.modules.associateBy(CheckpointModule::moduleId)
        val recoverableModules = mutableListOf<String>()
        for (oldModule in previous.modules) {
            val newModule = currentModules[oldModule.moduleId]
            if (newModule == null) {
                val authorizedCleanup = current.tombstones.any { tombstone ->
                    if (tombstone.moduleId != oldModule.moduleId) {
                        false
                    } else {
                        tombstone.previousEventCount >= oldModule.sequence &&
                            tombstone.previousEventHashes.hashAt(oldModule.sequence) == oldModule.headHash &&
                            (!oldModule.highRisk || tombstone.hadIntegrityIncident)
                    }
                }
                if (!authorizedCleanup) {
                    return PayloadTransition(
                        "Module audit history disappeared: ${oldModule.moduleId}"
                    )
                }
                continue
            }
            if (oldModule.highRisk && !newModule.highRisk) {
                return PayloadTransition(
                    "Module integrity-risk marker disappeared: ${oldModule.moduleId}"
                )
            }
            if (newModule.sequence == oldModule.sequence) {
                if (newModule.headHash != oldModule.headHash) {
                    if (isRecoverableRollback(oldModule, newModule, evidence[oldModule.moduleId])) {
                        recoverableModules += oldModule.moduleId
                        continue
                    }
                    return PayloadTransition(
                        "Module audit history was replaced: ${oldModule.moduleId}"
                    )
                }
                continue
            }

            if (
                newModule.sequence > oldModule.sequence &&
                newModule.eventHashes.hashAt(oldModule.sequence) == oldModule.headHash
            ) {
                continue
            }
            if (isRecoverableRollback(oldModule, newModule, evidence[oldModule.moduleId])) {
                recoverableModules += oldModule.moduleId
                continue
            }
            return PayloadTransition(
                if (newModule.sequence < oldModule.sequence) {
                    "Module audit history was rolled back: ${oldModule.moduleId}"
                } else {
                    "Module audit history no longer extends its checkpoint: ${oldModule.moduleId}"
                }
            )
        }
        for (newModule in current.modules) {
            if (previous.modules.any { it.moduleId == newModule.moduleId }) continue
            val replayed = current.tombstones.any { tombstone ->
                tombstone.moduleId == newModule.moduleId &&
                    newModule.eventHashes.startsWith(tombstone.previousEventHashes)
            }
            if (replayed) {
                return PayloadTransition(
                    "Compacted audit history was replayed: ${newModule.moduleId}"
                )
            }
        }
        return if (recoverableModules.isEmpty()) {
            PayloadTransition()
        } else {
            PayloadTransition(
                error = "Module audit history was rebuilt after an integrity failure: " +
                    recoverableModules.joinToString(),
                recoverableModules = recoverableModules.sorted(),
            )
        }
    }

    private fun isRecoverableRollback(
        previous: CheckpointModule,
        current: CheckpointModule,
        evidence: RecoveryEvidence?,
    ): Boolean {
        if (evidence == null) return false
        return isAuthenticatedAuditChainRebuild(
            previousHashes = previous.eventHashes,
            currentHashes = current.eventHashes,
            currentHighRisk = current.highRisk,
            hmacVerified = evidence.hmacVerified,
            eventCount = evidence.eventCount,
            lastSequence = evidence.lastSequence,
            lastPreviousHash = evidence.previousHash,
            lastKind = evidence.lastKind,
            corruptedFromSequence = evidence.corruptedFromSequence,
            reason = evidence.reason,
            quarantine = evidence.quarantine,
        )
    }

    private fun verifyOperationAuthorization(
        operation: CheckpointOperation,
        publicKey: PublicKey,
    ): Boolean = runCatching {
        val tokenBytes = operation.authorizationHex.hexToBytes()
        check(MessageDigest.getInstance("SHA-256").digest(tokenBytes).toHex() == operation.operationId)
        val token = JSONObject(String(tokenBytes, StandardCharsets.UTF_8))
        check(token.getInt("schema_version") == AUTHORIZATION_SCHEMA_VERSION)
        val action = token.getString("action")
        val inventoryHash = token.getString("inventory_hash")
        val argumentsHash = token.getString("arguments_hash")
        val keyId = token.getString("key_id")
        val challengeId = token.getString("challenge_id")
        val createdAtUnixSeconds = token.getLong("created_at_unix_seconds")
        check(action == operation.action)
        check(inventoryHash == operation.baseInventoryHash)
        check(argumentsHash == operation.argumentsHash)
        check(keyId == publicKey.authorizationKeyId())
        check(challengeId.isSha256Hex())
        check(createdAtUnixSeconds >= 0L)
        val message = buildString {
            append("kernelsu-audit-authorization-v2\n")
            append(action).append('\n')
            append(inventoryHash).append('\n')
            append(argumentsHash).append('\n')
            append(keyId).append('\n')
            append(challengeId).append('\n')
            append(createdAtUnixSeconds).append('\n')
        }.toByteArray(StandardCharsets.UTF_8)
        Signature.getInstance(SIGNATURE_ALGORITHM).run {
            initVerify(publicKey)
            update(message)
            verify(token.getString("signature_der_hex").hexToBytes())
        }
    }.getOrDefault(false)

    fun authorizationPublicKeyHex(): String {
        val publicKey = loadCurrentSigningKey().publicKey as? ECPublicKey
            ?: error("Manager audit signing key is unavailable")
        val encoded = byteArrayOf(UNCOMPRESSED_EC_POINT) +
            publicKey.w.affineX.toFixedUnsigned(P256_COORDINATE_BYTES) +
            publicKey.w.affineY.toFixedUnsigned(P256_COORDINATE_BYTES)
        return encoded.toHex()
    }

    fun authorizationKeyId(): String = MessageDigest.getInstance("SHA-256")
        .digest(authorizationPublicKeyHex().hexToBytes())
        .toHex()

    fun currentSealEnvelopeHex(): String =
        (readEnvelope() ?: error("Manager audit checkpoint is unavailable"))
            .toByteArray(StandardCharsets.UTF_8)
            .toHex()

    fun currentSealHash(): String = currentEnvelopeHash
        ?: error("Manager audit checkpoint has not been verified")

    fun acceptablePreviousSealHash(): String? = previousEnvelopeHash

    fun markSealSynchronized(sealHash: String) {
        check(sealHash == currentSealHash()) {
            "ksud acknowledged an unexpected Manager audit seal"
        }
        previousCheckpointFile.delete()
        previousEnvelopeHash = null
    }

    fun signAuditAuthorization(rawChallenge: String): String {
        val challenge = JSONObject(rawChallenge)
        check(challenge.getInt("schema_version") == AUTHORIZATION_SCHEMA_VERSION) {
            "Unsupported audit authorization challenge"
        }
        val action = challenge.getString("action")
        val inventoryHash = challenge.getString("inventory_hash")
        val argumentsHash = challenge.getString("arguments_hash")
        val keyId = challenge.getString("key_id")
        val challengeId = challenge.getString("challenge_id")
        val createdAtUnixSeconds = challenge.getLong("created_at_unix_seconds")
        check(keyId == authorizationKeyId()) {
            "Audit authorization key does not match this Manager"
        }
        check(inventoryHash == trustedInventoryHash) {
            "Audit inventory changed before authorization"
        }
        check(action.matches(Regex("[a-z-]{1,64}"))) { "Invalid audit authorization action" }
        check(inventoryHash.isSha256Hex()) { "Invalid audit inventory hash" }
        check(argumentsHash.isSha256Hex()) { "Invalid audit arguments hash" }
        check(challengeId.isSha256Hex()) { "Invalid ksud audit challenge id" }
        check(createdAtUnixSeconds >= 0L) { "Invalid ksud audit challenge timestamp" }
        val message = buildString {
            append("kernelsu-audit-authorization-v2\n")
            append(action).append('\n')
            append(inventoryHash).append('\n')
            append(argumentsHash).append('\n')
            append(keyId).append('\n')
            append(challengeId).append('\n')
            append(createdAtUnixSeconds).append('\n')
        }.toByteArray(StandardCharsets.UTF_8)
        val privateKey = loadCurrentSigningKey().privateKey
        val signature = Signature.getInstance(SIGNATURE_ALGORITHM).run {
            initSign(privateKey)
            update(message)
            sign()
        }
        return JSONObject()
            .put("schema_version", AUTHORIZATION_SCHEMA_VERSION)
            .put("action", action)
            .put("inventory_hash", inventoryHash)
            .put("arguments_hash", argumentsHash)
            .put("key_id", keyId)
            .put("challenge_id", challengeId)
            .put("created_at_unix_seconds", createdAtUnixSeconds)
            .put("signature_der_hex", signature.toHex())
            .toString()
            .toByteArray(StandardCharsets.UTF_8)
            .toHex()
    }

    private fun persist(
        payload: String,
        generation: Long,
        signingKey: AuditSigningKey,
        previousEnvelope: String?,
    ) {
        val payloadBase64 = Base64.encodeToString(
            payload.toByteArray(StandardCharsets.UTF_8),
            Base64.NO_WRAP,
        )
        val keyId = signingKey.publicKey.authorizationKeyId()
        val signable = signableBytes(
            ENVELOPE_SCHEMA_VERSION,
            generation,
            signingKey.backend,
            signingKey.protection,
            keyId,
            payloadBase64,
        )
        val signature = Signature.getInstance(SIGNATURE_ALGORITHM).run {
            initSign(signingKey.privateKey)
            update(signable)
            sign()
        }
        val envelope = JSONObject()
            .put("schema_version", ENVELOPE_SCHEMA_VERSION)
            .put("generation", generation)
            .put("key_backend", signingKey.backend.wireName)
            .put("key_protection", signingKey.protection.wireName)
            .put("key_id", keyId)
            .put("payload", payloadBase64)
            .put("signature", Base64.encodeToString(signature, Base64.NO_WRAP))
            .toString()
        if (previousEnvelope == null) {
            previousCheckpointFile.delete()
        } else {
            writeAtomicText(previousCheckpointFile, previousEnvelope)
        }
        writeAtomicText(checkpointFile, envelope)
    }

    private fun writeAtomicText(file: AtomicFile, value: String) {
        val output = file.startWrite()
        try {
            output.write(value.toByteArray(StandardCharsets.UTF_8))
            file.finishWrite(output)
        } catch (error: Throwable) {
            file.failWrite(output)
            throw error
        }
    }

    private fun readEnvelope(): String? {
        if (!checkpointFile.baseFile.isFile) return null
        return checkpointFile.openRead().bufferedReader(StandardCharsets.UTF_8).use { it.readText() }
    }

    private fun readPreviousEnvelope(): String? {
        if (!previousCheckpointFile.baseFile.isFile) return null
        return previousCheckpointFile.openRead()
            .bufferedReader(StandardCharsets.UTF_8)
            .use { it.readText() }
    }

    private fun transitionBase(
        currentText: String,
        current: CheckpointEnvelope,
        publicKey: PublicKey,
        sealedEnvelopeHash: String?,
    ): Pair<String, CheckpointEnvelope> {
        val previousText = readPreviousEnvelope() ?: return currentText to current
        if (previousText == currentText) {
            previousCheckpointFile.delete()
            return currentText to current
        }
        val previous = parseEnvelope(previousText)
        check(verifyEnvelope(previous, publicKey)) {
            "Previous Manager checkpoint signature is invalid"
        }
        check(previous.keyId == current.keyId && previous.backend == current.backend) {
            "Manager checkpoint transition identity changed"
        }
        check(Math.addExact(previous.generation, 1L) == current.generation) {
            "Manager checkpoint transition generation is inconsistent"
        }
        val currentHash = currentText.sha256Hex()
        val previousHash = previousText.sha256Hex()
        return if (
            selectAuditTransitionBaseHash(sealedEnvelopeHash, currentHash, previousHash) == currentHash
        ) {
            currentText to current
        } else {
            previousText to previous
        }
    }

    private fun verifyEnvelope(envelope: CheckpointEnvelope, publicKey: PublicKey): Boolean {
        return Signature.getInstance(SIGNATURE_ALGORITHM).run {
            initVerify(publicKey)
            update(
                signableBytes(
                    envelope.schemaVersion,
                    envelope.generation,
                    envelope.backend,
                    envelope.protection,
                    envelope.keyId,
                    envelope.payloadBase64,
                )
            )
            verify(Base64.decode(envelope.signatureBase64, Base64.DEFAULT))
        }
    }

    private fun createBestAvailableSigningKey(): AuditSigningKey = runCatching {
        generateAndroidKey()
        loadAndroidSigningKey().also(::selfTest)
    }.getOrElse { androidError ->
        runCatching {
            val keyStore = loadKeyStore()
            if (keyStore.containsAlias(KEY_ALIAS)) keyStore.deleteEntry(KEY_ALIAS)
        }
        runCatching {
            generateSoftwareSigningKey()
        }.getOrElse { softwareError ->
            throw IllegalStateException(
                "No audit signing backend is available; Android Keystore: " +
                    "${androidError.message}; software fallback: ${softwareError.message}",
                softwareError,
            )
        }
    }

    private fun generateAndroidKey() {
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEY_STORE).run {
            initialize(
                KeyGenParameterSpec.Builder(
                    KEY_ALIAS,
                    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY,
                )
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setUserAuthenticationRequired(false)
                    .build()
            )
            generateKeyPair()
        }
    }

    private fun loadCurrentSigningKey(): AuditSigningKey {
        val envelope = readEnvelope()?.let(::parseEnvelope)
            ?: error("Manager audit checkpoint is unavailable")
        return loadSigningKey(envelope.backend).also { signingKey ->
            validateAuditKeyProtectionTransition(envelope.protection, signingKey.protection)
            check(envelope.keyId == signingKey.publicKey.authorizationKeyId())
        }
    }

    private fun loadSigningKey(backend: AuditKeyBackend): AuditSigningKey = when (backend) {
        AuditKeyBackend.AndroidKeyStore -> loadAndroidSigningKey()
        AuditKeyBackend.SoftwareFile -> loadSoftwareSigningKey()
    }

    private fun loadAndroidSigningKey(): AuditSigningKey {
        val keyStore = loadKeyStore()
        val privateKey = keyStore.getKey(KEY_ALIAS, null) as? PrivateKey
            ?: error("Manager Keystore key is missing")
        val publicKey = keyStore.getCertificate(KEY_ALIAS)?.publicKey
            ?: error("Manager Keystore certificate is missing")
        val protection = runCatching {
            KeyFactory.getInstance(privateKey.algorithm, ANDROID_KEY_STORE)
                .getKeySpec(privateKey, KeyInfo::class.java)
                .securityLevel
        }.fold(
            onSuccess = { securityLevel ->
                when (securityLevel) {
                    KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
                    KeyProperties.SECURITY_LEVEL_STRONGBOX -> AuditKeyProtection.Hardware
                    else -> AuditKeyProtection.Degraded
                }
            },
            onFailure = { AuditKeyProtection.Degraded },
        )
        return AuditSigningKey(
            backend = AuditKeyBackend.AndroidKeyStore,
            protection = protection,
            privateKey = privateKey,
            publicKey = publicKey,
        )
    }

    private fun generateSoftwareSigningKey(): AuditSigningKey {
        val keyPair = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC).run {
            initialize(ECGenParameterSpec("secp256r1"), SecureRandom())
            generateKeyPair()
        }
        val signingKey = AuditSigningKey(
            backend = AuditKeyBackend.SoftwareFile,
            protection = AuditKeyProtection.Emergency,
            privateKey = keyPair.private,
            publicKey = keyPair.public,
        ).also(::selfTest)
        val json = JSONObject()
            .put("schema_version", SOFTWARE_KEY_SCHEMA_VERSION)
            .put("private_key", Base64.encodeToString(keyPair.private.encoded, Base64.NO_WRAP))
            .put("public_key", Base64.encodeToString(keyPair.public.encoded, Base64.NO_WRAP))
            .toString()
        val output = softwareKeyFile.startWrite()
        try {
            output.write(json.toByteArray(StandardCharsets.UTF_8))
            softwareKeyFile.finishWrite(output)
        } catch (error: Throwable) {
            softwareKeyFile.failWrite(output)
            throw error
        }
        return signingKey
    }

    private fun discardSigningKey(backend: AuditKeyBackend) {
        when (backend) {
            AuditKeyBackend.AndroidKeyStore -> runCatching {
                val keyStore = loadKeyStore()
                if (keyStore.containsAlias(KEY_ALIAS)) keyStore.deleteEntry(KEY_ALIAS)
            }
            AuditKeyBackend.SoftwareFile -> softwareKeyFile.delete()
        }
        activeProtection = AuditKeyProtection.Unavailable
    }

    private fun loadSoftwareSigningKey(): AuditSigningKey {
        check(softwareKeyFile.baseFile.isFile) { "Manager emergency signing key is missing" }
        val json = softwareKeyFile.openRead().bufferedReader(StandardCharsets.UTF_8).use {
            JSONObject(it.readText())
        }
        check(json.getInt("schema_version") == SOFTWARE_KEY_SCHEMA_VERSION) {
            "Unsupported Manager emergency signing key schema"
        }
        val factory = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC)
        val privateKey = factory.generatePrivate(
            PKCS8EncodedKeySpec(Base64.decode(json.getString("private_key"), Base64.DEFAULT))
        )
        val publicKey = factory.generatePublic(
            X509EncodedKeySpec(Base64.decode(json.getString("public_key"), Base64.DEFAULT))
        )
        return AuditSigningKey(
            backend = AuditKeyBackend.SoftwareFile,
            protection = AuditKeyProtection.Emergency,
            privateKey = privateKey,
            publicKey = publicKey,
        ).also(::selfTest)
    }

    private fun selfTest(signingKey: AuditSigningKey) {
        val probe = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val signature = Signature.getInstance(SIGNATURE_ALGORITHM).run {
            initSign(signingKey.privateKey)
            update(probe)
            sign()
        }
        check(Signature.getInstance(SIGNATURE_ALGORITHM).run {
            initVerify(signingKey.publicKey)
            update(probe)
            verify(signature)
        }) { "Audit signing key self-test failed" }
    }

    private fun loadKeyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEY_STORE).apply {
        load(null)
    }

    private fun parseEnvelope(raw: String): CheckpointEnvelope {
        val json = JSONObject(raw)
        val schemaVersion = json.getInt("schema_version")
        check(schemaVersion == ENVELOPE_SCHEMA_VERSION) {
            "Unsupported Manager checkpoint schema"
        }
        val generation = json.getLong("generation")
        check(generation > 0L) { "Invalid Manager checkpoint generation" }
        val payloadBase64 = json.getString("payload")
        val payload = String(Base64.decode(payloadBase64, Base64.DEFAULT), StandardCharsets.UTF_8)
        return CheckpointEnvelope(
            schemaVersion = schemaVersion,
            generation = generation,
            backend = AuditKeyBackend.fromWireName(json.getString("key_backend")),
            protection = AuditKeyProtection.entries.firstOrNull {
                it.wireName == json.getString("key_protection")
            } ?: error("Unknown Manager checkpoint protection level"),
            keyId = json.getString("key_id").also { check(it.isSha256Hex()) },
            payloadBase64 = payloadBase64,
            payload = payload,
            signatureBase64 = json.getString("signature"),
        )
    }

    private fun parsePayload(raw: String): CheckpointPayload {
        val json = JSONObject(raw)
        val schemaVersion = json.getInt("schema_version")
        check(schemaVersion == CHECKPOINT_SCHEMA_VERSION) {
            "Unsupported audit checkpoint payload schema"
        }
        return CheckpointPayload(
            schemaVersion = schemaVersion,
            hmacKeyId = json.getString("hmac_key_id"),
            nextHmacKeyId = json.getString("next_hmac_key_id").also {
                check(it.isSha256Hex())
            },
            inventoryHash = json.getString("inventory_hash").also {
                check(it.isSha256Hex())
            },
            modules = json.getJSONArray("modules").mapObjects { module ->
                CheckpointModule(
                    moduleId = module.getString("module_id"),
                    sequence = module.getLong("sequence"),
                    headHash = module.getString("head_hash"),
                    eventHashes = module.optJSONArray("event_hashes")
                        ?.mapStrings()
                        .orEmpty(),
                    highRisk = module.getBoolean("high_risk"),
                ).also { parsed ->
                    check(parsed.sequence == parsed.eventHashes.size.toLong()) {
                        "Checkpoint event hash count mismatch for ${parsed.moduleId}"
                    }
                    check(parsed.eventHashes.lastOrNull() == parsed.headHash) {
                        "Checkpoint head hash mismatch for ${parsed.moduleId}"
                    }
                }
            },
            tombstones = json.optJSONArray("tombstones")?.mapObjects { tombstone ->
                CheckpointTombstone(
                    moduleId = tombstone.getString("module_id"),
                    clearedAtUnixSeconds = tombstone.getLong("cleared_at_unix_seconds"),
                    previousEventCount = tombstone.getLong("previous_event_count"),
                    previousHeadHash = tombstone.getString("previous_head_hash"),
                    previousEventHashes = tombstone.getJSONArray("previous_event_hashes")
                        .mapStrings(),
                    hadIntegrityIncident = tombstone.getBoolean("had_integrity_incident"),
                )
            }.orEmpty(),
            operations = json.getJSONArray("operations").mapObjects { operation ->
                CheckpointOperation(
                    operationId = operation.getString("operation_id").also {
                        check(it.isSha256Hex())
                    },
                    action = operation.getString("action"),
                    baseInventoryHash = operation.getString("base_inventory_hash").also {
                        check(it.isSha256Hex())
                    },
                    argumentsHash = operation.getString("arguments_hash").also {
                        check(it.isSha256Hex())
                    },
                    authorizationHex = operation.getString("authorization_hex"),
                    targets = operation.getJSONArray("targets").mapStrings(),
                    completedTargets = operation.getJSONArray("completed_targets").mapStrings(),
                    state = operation.getString("state").also {
                        check(it == "applying" || it == "applied" || it == "interrupted")
                    },
                    error = if (operation.isNull("error")) null else operation.getString("error"),
                )
            },
        )
    }

    private fun parseRecoveryEvidence(raw: String): Map<String, RecoveryEvidence> {
        val histories = JSONArray(raw)
        return (0 until histories.length()).associate { index ->
            val history = histories.getJSONObject(index)
            val status = history.getJSONObject("status")
            val moduleId = status.getString("module_id")
            val events = history.optJSONArray("events") ?: JSONArray()
            val lastEvent = events.optJSONObject(events.length() - 1)
            val kind = lastEvent?.optJSONObject("kind")
            moduleId to RecoveryEvidence(
                hmacVerified = status.optBoolean("hmac_verified", false),
                eventCount = status.optLong("event_count", -1L),
                lastSequence = lastEvent?.optLong("sequence", -1L) ?: -1L,
                previousHash = lastEvent?.optString("previous_hash").orEmpty(),
                lastKind = kind?.optString("type").orEmpty(),
                corruptedFromSequence = kind?.optLong("corrupted_from_sequence", -1L) ?: -1L,
                reason = kind?.optString("reason")?.takeIf(String::isNotBlank),
                quarantine = kind?.optString("quarantine")?.takeIf(String::isNotBlank),
            )
        }
    }

    private fun signableBytes(
        schemaVersion: Int,
        generation: Long,
        backend: AuditKeyBackend,
        protection: AuditKeyProtection,
        keyId: String,
        payloadBase64: String,
    ): ByteArray =
        "$schemaVersion\n$generation\n${backend.wireName}\n${protection.wireName}\n$keyId\n$payloadBase64"
            .toByteArray(StandardCharsets.UTF_8)

    private fun compromised(
        detail: String,
        recoverableModules: List<String> = emptyList(),
    ): AuditCheckpointVerification {
        trustedInventoryHash = null
        previousEnvelopeHash = null
        currentEnvelopeHash = null
        observedSealHash = null
        return AuditCheckpointVerification(
            trust = AuditCheckpointTrust.Compromised,
            detail = detail,
            protection = activeProtection,
            recoverableModules = recoverableModules,
        )
    }

    private data class PayloadTransition(
        val error: String? = null,
        val recoverableModules: List<String> = emptyList(),
    )

    private data class RecoveryEvidence(
        val hmacVerified: Boolean,
        val eventCount: Long,
        val lastSequence: Long,
        val previousHash: String,
        val lastKind: String,
        val corruptedFromSequence: Long,
        val reason: String?,
        val quarantine: String?,
    )

    private data class CheckpointEnvelope(
        val schemaVersion: Int,
        val generation: Long,
        val backend: AuditKeyBackend,
        val protection: AuditKeyProtection,
        val keyId: String,
        val payloadBase64: String,
        val payload: String,
        val signatureBase64: String,
    )

    private data class CheckpointPayload(
        val schemaVersion: Int,
        val hmacKeyId: String,
        val nextHmacKeyId: String,
        val inventoryHash: String,
        val modules: List<CheckpointModule>,
        val tombstones: List<CheckpointTombstone>,
        val operations: List<CheckpointOperation>,
    )

    private data class CheckpointOperation(
        val operationId: String,
        val action: String,
        val baseInventoryHash: String,
        val argumentsHash: String,
        val authorizationHex: String,
        val targets: List<String>,
        val completedTargets: List<String>,
        val state: String,
        val error: String?,
    )

    private data class CheckpointModule(
        val moduleId: String,
        val sequence: Long,
        val headHash: String,
        val eventHashes: List<String>,
        val highRisk: Boolean,
    )

    private data class CheckpointTombstone(
        val moduleId: String,
        val clearedAtUnixSeconds: Long,
        val previousEventCount: Long,
        val previousHeadHash: String,
        val previousEventHashes: List<String>,
        val hadIntegrityIncident: Boolean,
    )

    private data class AuditSigningKey(
        val backend: AuditKeyBackend,
        val protection: AuditKeyProtection,
        val privateKey: PrivateKey,
        val publicKey: PublicKey,
    )

    private enum class AuditKeyBackend(val wireName: String) {
        AndroidKeyStore("android_keystore"),
        SoftwareFile("software_file");

        companion object {
            fun fromWireName(value: String): AuditKeyBackend = entries.firstOrNull {
                it.wireName == value
            } ?: error("Unknown Manager checkpoint key backend")
        }
    }

    private inline fun <T> JSONArray.mapObjects(transform: (JSONObject) -> T): List<T> =
        (0 until length()).map { index -> transform(getJSONObject(index)) }

    private fun JSONArray.mapStrings(): List<String> =
        (0 until length()).map { index -> getString(index) }

    private fun <T> List<T>.startsWith(prefix: List<T>): Boolean =
        size >= prefix.size && subList(0, prefix.size) == prefix

    private fun List<String>.hashAt(sequence: Long): String? {
        if (sequence <= 0L || sequence > Int.MAX_VALUE.toLong()) return null
        return getOrNull(sequence.toInt() - 1)
    }

    private fun BigInteger.toFixedUnsigned(size: Int): ByteArray {
        val bytes = toByteArray()
        val unsigned = if (bytes.size > size && bytes.first() == 0.toByte()) {
            bytes.copyOfRange(1, bytes.size)
        } else {
            bytes
        }
        check(unsigned.size <= size) { "EC coordinate exceeds P-256 size" }
        return ByteArray(size - unsigned.size) + unsigned
    }

    private fun ByteArray.toHex(): String =
        joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }

    private fun String.hexToBytes(): ByteArray {
        check(length % 2 == 0 && all { it.isHexDigit() }) { "Invalid hexadecimal input" }
        return chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }

    private fun String.isSha256Hex(): Boolean = length == 64 && all { it.isHexDigit() }

    private fun String.sha256Hex(): String = MessageDigest.getInstance("SHA-256")
        .digest(toByteArray(StandardCharsets.UTF_8))
        .toHex()

    private fun PublicKey.authorizationKeyId(): String {
        val ecPublicKey = this as? ECPublicKey ?: error("Audit authorization key is not EC")
        val encodedPoint = byteArrayOf(UNCOMPRESSED_EC_POINT) +
            ecPublicKey.w.affineX.toFixedUnsigned(P256_COORDINATE_BYTES) +
            ecPublicKey.w.affineY.toFixedUnsigned(P256_COORDINATE_BYTES)
        return MessageDigest.getInstance("SHA-256").digest(encodedPoint).toHex()
    }

    private fun Char.isHexDigit(): Boolean =
        this in '0'..'9' || this in 'a'..'f' || this in 'A'..'F'

    private companion object {
        const val ANDROID_KEY_STORE = "AndroidKeyStore"
        const val KEY_ALIAS = "kernelsu.module_audit.checkpoint.v1"
        const val SIGNATURE_ALGORITHM = "SHA256withECDSA"
        const val CHECKPOINT_FILE_NAME = "module_audit_checkpoint.json"
        const val PREVIOUS_CHECKPOINT_FILE_NAME = "module_audit_checkpoint_previous.json"
        const val SOFTWARE_KEY_FILE_NAME = "module_audit_emergency_key.json"
        const val ENVELOPE_SCHEMA_VERSION = 2
        const val SOFTWARE_KEY_SCHEMA_VERSION = 1
        const val CHECKPOINT_SCHEMA_VERSION = 5
        const val AUTHORIZATION_SCHEMA_VERSION = 2
        const val P256_COORDINATE_BYTES = 32
        const val UNCOMPRESSED_EC_POINT: Byte = 0x04
    }
}
