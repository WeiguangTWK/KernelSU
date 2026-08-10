package me.weishu.kernelsu.security

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import android.util.Base64
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.nio.charset.StandardCharsets
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.spec.ECGenParameterSpec

enum class AuditCheckpointTrust(val wireName: String) {
    NotConfigured("not_configured"),
    Initialized("keystore_initialized"),
    Verified("keystore_verified"),
    Compromised("keystore_compromised"),
}

data class AuditCheckpointVerification(
    val trust: AuditCheckpointTrust,
    val detail: String? = null,
)

class ModuleAuditCheckpointStore(context: Context) {
    private val checkpointFile = AtomicFile(File(context.noBackupFilesDir, CHECKPOINT_FILE_NAME))

    fun reconcile(rawPayload: String): AuditCheckpointVerification =
        runCatching {
            val current = parsePayload(rawPayload)
            val keyStore = loadKeyStore()
            val envelopeText = readEnvelope()
            val hasKey = keyStore.containsAlias(KEY_ALIAS)

            when {
                envelopeText == null && !hasKey -> {
                    generateKey()
                    persist(rawPayload, generation = 1L)
                    AuditCheckpointVerification(AuditCheckpointTrust.Initialized)
                }

                envelopeText == null -> compromised("Manager checkpoint data is missing")
                !hasKey -> compromised("Manager Keystore key is missing")
                else -> {
                    val envelope = parseEnvelope(envelopeText)
                    if (!verifyEnvelope(envelope, keyStore)) {
                        return@runCatching compromised("Manager checkpoint signature is invalid")
                    }
                    val previous = parsePayload(envelope.payload)
                    comparePayloads(previous, current)?.let {
                        return@runCatching compromised(it)
                    }
                    if (previous != current) {
                        persist(rawPayload, Math.addExact(envelope.generation, 1L))
                    }
                    AuditCheckpointVerification(AuditCheckpointTrust.Verified)
                }
            }
        }.getOrElse { error ->
            compromised(error.message ?: error::class.java.simpleName)
        }

    fun checkpointUnavailable(detail: String): AuditCheckpointVerification = runCatching {
        val keyStore = loadKeyStore()
        val hasEnvelope = checkpointFile.baseFile.isFile
        if (hasEnvelope || keyStore.containsAlias(KEY_ALIAS)) {
            compromised("Audit store unavailable after checkpoint: $detail")
        } else {
            AuditCheckpointVerification(AuditCheckpointTrust.NotConfigured, detail)
        }
    }.getOrElse { compromised("Unable to inspect Manager checkpoint: ${it.message ?: detail}") }

    private fun comparePayloads(
        previous: CheckpointPayload,
        current: CheckpointPayload,
    ): String? {
        if (previous.schemaVersion != current.schemaVersion) {
            return "Audit checkpoint schema changed unexpectedly"
        }
        if (previous.hmacKeyId != current.hmacKeyId) {
            return "Audit HMAC key identity changed"
        }

        val currentTombstones = current.tombstones.toSet()
        val missingTombstones = previous.tombstones.filterNot(currentTombstones::contains)
        if (missingTombstones.isNotEmpty()) {
            return "Authenticated cleanup records disappeared: " +
                missingTombstones.joinToString { it.moduleId }
        }

        val currentModules = current.modules.associateBy(CheckpointModule::moduleId)
        for (oldModule in previous.modules) {
            val newModule = currentModules[oldModule.moduleId]
            if (newModule == null) {
                val authorizedCleanup = current.tombstones.any { tombstone ->
                    if (tombstone.moduleId != oldModule.moduleId) {
                        false
                    } else if (tombstone.previousEventHashes.isEmpty()) {
                        tombstone.previousEventCount == oldModule.sequence &&
                            tombstone.previousHeadHash == oldModule.headHash
                    } else {
                        tombstone.previousEventCount >= oldModule.sequence &&
                            tombstone.previousEventHashes.hashAt(oldModule.sequence) == oldModule.headHash
                    }
                }
                if (!authorizedCleanup) {
                    return "Module audit history disappeared: ${oldModule.moduleId}"
                }
                continue
            }
            if (newModule.sequence < oldModule.sequence) {
                return "Module audit history was rolled back: ${oldModule.moduleId}"
            }
            if (oldModule.highRisk && !newModule.highRisk) {
                return "Module integrity-risk marker disappeared: ${oldModule.moduleId}"
            }
            if (newModule.sequence == oldModule.sequence) {
                if (newModule.headHash != oldModule.headHash) {
                    return "Module audit history was replaced: ${oldModule.moduleId}"
                }
                continue
            }

            if (newModule.eventHashes.hashAt(oldModule.sequence) != oldModule.headHash) {
                return "Module audit history no longer extends its checkpoint: ${oldModule.moduleId}"
            }
        }
        return null
    }

    private fun persist(payload: String, generation: Long) {
        val payloadBase64 = Base64.encodeToString(
            payload.toByteArray(StandardCharsets.UTF_8),
            Base64.NO_WRAP,
        )
        val signable = signableBytes(generation, payloadBase64)
        val keyStore = loadKeyStore()
        val privateKey = keyStore.getKey(KEY_ALIAS, null)
            ?: error("Manager Keystore signing key is unavailable")
        val signature = Signature.getInstance(SIGNATURE_ALGORITHM).run {
            initSign(privateKey as java.security.PrivateKey)
            update(signable)
            sign()
        }
        val envelope = JSONObject()
            .put("schema_version", ENVELOPE_SCHEMA_VERSION)
            .put("generation", generation)
            .put("payload", payloadBase64)
            .put("signature", Base64.encodeToString(signature, Base64.NO_WRAP))
            .toString()
        val output = checkpointFile.startWrite()
        try {
            output.write(envelope.toByteArray(StandardCharsets.UTF_8))
            checkpointFile.finishWrite(output)
        } catch (error: Throwable) {
            checkpointFile.failWrite(output)
            throw error
        }
    }

    private fun readEnvelope(): String? {
        if (!checkpointFile.baseFile.isFile) return null
        return checkpointFile.openRead().bufferedReader(StandardCharsets.UTF_8).use { it.readText() }
    }

    private fun verifyEnvelope(envelope: CheckpointEnvelope, keyStore: KeyStore): Boolean {
        val certificate = keyStore.getCertificate(KEY_ALIAS) ?: return false
        return Signature.getInstance(SIGNATURE_ALGORITHM).run {
            initVerify(certificate.publicKey)
            update(signableBytes(envelope.generation, envelope.payloadBase64))
            verify(Base64.decode(envelope.signatureBase64, Base64.DEFAULT))
        }
    }

    private fun generateKey() {
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

    private fun loadKeyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEY_STORE).apply {
        load(null)
    }

    private fun parseEnvelope(raw: String): CheckpointEnvelope {
        val json = JSONObject(raw)
        check(json.getInt("schema_version") == ENVELOPE_SCHEMA_VERSION) {
            "Unsupported Manager checkpoint schema"
        }
        val generation = json.getLong("generation")
        check(generation > 0L) { "Invalid Manager checkpoint generation" }
        val payloadBase64 = json.getString("payload")
        val payload = String(Base64.decode(payloadBase64, Base64.DEFAULT), StandardCharsets.UTF_8)
        return CheckpointEnvelope(
            generation = generation,
            payloadBase64 = payloadBase64,
            payload = payload,
            signatureBase64 = json.getString("signature"),
        )
    }

    private fun parsePayload(raw: String): CheckpointPayload {
        val json = JSONObject(raw)
        check(json.getInt("schema_version") == CHECKPOINT_SCHEMA_VERSION) {
            "Unsupported audit checkpoint payload schema"
        }
        return CheckpointPayload(
            schemaVersion = json.getInt("schema_version"),
            hmacKeyId = json.getString("hmac_key_id"),
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
                    previousEventHashes = tombstone.optJSONArray("previous_event_hashes")
                        ?.mapStrings()
                        .orEmpty(),
                    hadIntegrityIncident = tombstone.getBoolean("had_integrity_incident"),
                )
            }.orEmpty(),
        )
    }

    private fun signableBytes(generation: Long, payloadBase64: String): ByteArray =
        "$ENVELOPE_SCHEMA_VERSION\n$generation\n$payloadBase64"
            .toByteArray(StandardCharsets.UTF_8)

    private fun compromised(detail: String) = AuditCheckpointVerification(
        trust = AuditCheckpointTrust.Compromised,
        detail = detail,
    )

    private data class CheckpointEnvelope(
        val generation: Long,
        val payloadBase64: String,
        val payload: String,
        val signatureBase64: String,
    )

    private data class CheckpointPayload(
        val schemaVersion: Int,
        val hmacKeyId: String,
        val modules: List<CheckpointModule>,
        val tombstones: List<CheckpointTombstone>,
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

    private inline fun <T> JSONArray.mapObjects(transform: (JSONObject) -> T): List<T> =
        (0 until length()).map { index -> transform(getJSONObject(index)) }

    private fun JSONArray.mapStrings(): List<String> =
        (0 until length()).map { index -> getString(index) }

    private fun List<String>.hashAt(sequence: Long): String? {
        if (sequence <= 0L || sequence > Int.MAX_VALUE.toLong()) return null
        return getOrNull(sequence.toInt() - 1)
    }

    private companion object {
        const val ANDROID_KEY_STORE = "AndroidKeyStore"
        const val KEY_ALIAS = "kernelsu.module_audit.checkpoint.v1"
        const val SIGNATURE_ALGORITHM = "SHA256withECDSA"
        const val CHECKPOINT_FILE_NAME = "module_audit_checkpoint.json"
        const val ENVELOPE_SCHEMA_VERSION = 1
        const val CHECKPOINT_SCHEMA_VERSION = 2
    }
}
