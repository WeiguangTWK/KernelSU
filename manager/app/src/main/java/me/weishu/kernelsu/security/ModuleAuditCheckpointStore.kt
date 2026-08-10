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

class ModuleAuditCheckpointStore(context: Context) {
    private val checkpointFile = AtomicFile(File(context.noBackupFilesDir, CHECKPOINT_FILE_NAME))
    private val softwareKeyFile = AtomicFile(File(context.noBackupFilesDir, SOFTWARE_KEY_FILE_NAME))
    @Volatile
    private var trustedInventoryHash: String? = null
    @Volatile
    private var activeProtection = AuditKeyProtection.Unavailable

    fun reconcile(rawPayload: String): AuditCheckpointVerification =
        runCatching {
            val current = parsePayload(rawPayload)
            check(current.schemaVersion == CHECKPOINT_SCHEMA_VERSION) {
                "Unsupported current audit checkpoint payload schema"
            }
            check(current.inventoryHash?.isSha256Hex() == true) {
                "Current audit checkpoint has no valid inventory hash"
            }
            val envelopeText = readEnvelope()
            val hasAndroidKey = runCatching {
                loadKeyStore().containsAlias(KEY_ALIAS)
            }.getOrDefault(false)
            val hasSoftwareKey = softwareKeyFile.baseFile.isFile

            when {
                envelopeText == null && !hasAndroidKey && !hasSoftwareKey -> {
                    val signingKey = createBestAvailableSigningKey()
                    activeProtection = signingKey.protection
                    try {
                        persist(rawPayload, generation = 1L, signingKey = signingKey)
                    } catch (error: Throwable) {
                        discardSigningKey(signingKey.backend)
                        throw error
                    }
                    trustedInventoryHash = current.inventoryHash
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
                    if (
                        envelope.keyId != null &&
                        envelope.keyId != signingKey.publicKey.keyId()
                    ) {
                        return@runCatching compromised("Manager checkpoint key identity changed")
                    }
                    validateAuditKeyProtectionTransition(
                        envelope.protection,
                        signingKey.protection,
                    )
                    if (!verifyEnvelope(envelope, signingKey.publicKey)) {
                        return@runCatching compromised("Manager checkpoint signature is invalid")
                    }
                    val previous = parsePayload(envelope.payload)
                    comparePayloads(previous, current)?.let {
                        return@runCatching compromised(it)
                    }
                    if (
                        previous != current ||
                        envelope.schemaVersion != ENVELOPE_SCHEMA_VERSION ||
                        envelope.protection != signingKey.protection
                    ) {
                        persist(
                            rawPayload,
                            Math.addExact(envelope.generation, 1L),
                            signingKey,
                        )
                    }
                    trustedInventoryHash = current.inventoryHash
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

    private fun comparePayloads(
        previous: CheckpointPayload,
        current: CheckpointPayload,
    ): String? {
        if (
            previous.schemaVersion != current.schemaVersion &&
            !(previous.schemaVersion == LEGACY_CHECKPOINT_SCHEMA_VERSION &&
                current.schemaVersion == CHECKPOINT_SCHEMA_VERSION)
        ) {
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

    fun signAuditAuthorization(rawChallenge: String): String {
        val challenge = JSONObject(rawChallenge)
        check(challenge.getInt("schema_version") == AUTHORIZATION_SCHEMA_VERSION) {
            "Unsupported audit authorization challenge"
        }
        val action = challenge.getString("action")
        val inventoryHash = challenge.getString("inventory_hash")
        val argumentsHash = challenge.getString("arguments_hash")
        val keyId = challenge.getString("key_id")
        check(keyId == authorizationKeyId()) {
            "Audit authorization key does not match this Manager"
        }
        check(inventoryHash == trustedInventoryHash) {
            "Audit inventory changed before authorization"
        }
        check(action.matches(Regex("[a-z-]{1,64}"))) { "Invalid audit authorization action" }
        check(inventoryHash.isSha256Hex()) { "Invalid audit inventory hash" }
        check(argumentsHash.isSha256Hex()) { "Invalid audit arguments hash" }

        val nonceHex = ByteArray(AUTHORIZATION_NONCE_BYTES).also {
            SecureRandom().nextBytes(it)
        }.toHex()
        val message = buildString {
            append("kernelsu-audit-authorization-v1\n")
            append(action).append('\n')
            append(inventoryHash).append('\n')
            append(argumentsHash).append('\n')
            append(nonceHex).append('\n')
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
            .put("nonce_hex", nonceHex)
            .put("signature_der_hex", signature.toHex())
            .toString()
            .toByteArray(StandardCharsets.UTF_8)
            .toHex()
    }

    private fun persist(payload: String, generation: Long, signingKey: AuditSigningKey) {
        val payloadBase64 = Base64.encodeToString(
            payload.toByteArray(StandardCharsets.UTF_8),
            Base64.NO_WRAP,
        )
        val keyId = signingKey.publicKey.keyId()
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
            envelope.keyId?.let { check(it == signingKey.publicKey.keyId()) }
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
        check(
            schemaVersion == LEGACY_ENVELOPE_SCHEMA_VERSION ||
                schemaVersion == ENVELOPE_SCHEMA_VERSION
        ) {
            "Unsupported Manager checkpoint schema"
        }
        val generation = json.getLong("generation")
        check(generation > 0L) { "Invalid Manager checkpoint generation" }
        val payloadBase64 = json.getString("payload")
        val payload = String(Base64.decode(payloadBase64, Base64.DEFAULT), StandardCharsets.UTF_8)
        return CheckpointEnvelope(
            schemaVersion = schemaVersion,
            generation = generation,
            backend = if (schemaVersion == LEGACY_ENVELOPE_SCHEMA_VERSION) {
                AuditKeyBackend.AndroidKeyStore
            } else {
                AuditKeyBackend.fromWireName(json.getString("key_backend"))
            },
            protection = if (schemaVersion == LEGACY_ENVELOPE_SCHEMA_VERSION) {
                null
            } else {
                AuditKeyProtection.entries.firstOrNull {
                    it.wireName == json.getString("key_protection")
                } ?: error("Unknown Manager checkpoint protection level")
            },
            keyId = if (schemaVersion == LEGACY_ENVELOPE_SCHEMA_VERSION) {
                null
            } else {
                json.getString("key_id").also { check(it.isSha256Hex()) }
            },
            payloadBase64 = payloadBase64,
            payload = payload,
            signatureBase64 = json.getString("signature"),
        )
    }

    private fun parsePayload(raw: String): CheckpointPayload {
        val json = JSONObject(raw)
        val schemaVersion = json.getInt("schema_version")
        check(
            schemaVersion == LEGACY_CHECKPOINT_SCHEMA_VERSION ||
                schemaVersion == CHECKPOINT_SCHEMA_VERSION
        ) {
            "Unsupported audit checkpoint payload schema"
        }
        return CheckpointPayload(
            schemaVersion = schemaVersion,
            hmacKeyId = json.getString("hmac_key_id"),
            inventoryHash = json.optString("inventory_hash").takeIf(String::isNotBlank),
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

    private fun signableBytes(
        schemaVersion: Int,
        generation: Long,
        backend: AuditKeyBackend,
        protection: AuditKeyProtection?,
        keyId: String?,
        payloadBase64: String,
    ): ByteArray = if (schemaVersion == LEGACY_ENVELOPE_SCHEMA_VERSION) {
        "$LEGACY_ENVELOPE_SCHEMA_VERSION\n$generation\n$payloadBase64"
            .toByteArray(StandardCharsets.UTF_8)
    } else {
        "$schemaVersion\n$generation\n${backend.wireName}\n${protection?.wireName}\n$keyId\n$payloadBase64"
            .toByteArray(StandardCharsets.UTF_8)
    }

    private fun compromised(detail: String): AuditCheckpointVerification {
        trustedInventoryHash = null
        return AuditCheckpointVerification(
            trust = AuditCheckpointTrust.Compromised,
            detail = detail,
            protection = activeProtection,
        )
    }

    private data class CheckpointEnvelope(
        val schemaVersion: Int,
        val generation: Long,
        val backend: AuditKeyBackend,
        val protection: AuditKeyProtection?,
        val keyId: String?,
        val payloadBase64: String,
        val payload: String,
        val signatureBase64: String,
    )

    private data class CheckpointPayload(
        val schemaVersion: Int,
        val hmacKeyId: String,
        val inventoryHash: String?,
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

    private fun PublicKey.keyId(): String = MessageDigest.getInstance("SHA-256")
        .digest(encoded)
        .toHex()

    private fun Char.isHexDigit(): Boolean =
        this in '0'..'9' || this in 'a'..'f' || this in 'A'..'F'

    private companion object {
        const val ANDROID_KEY_STORE = "AndroidKeyStore"
        const val KEY_ALIAS = "kernelsu.module_audit.checkpoint.v1"
        const val SIGNATURE_ALGORITHM = "SHA256withECDSA"
        const val CHECKPOINT_FILE_NAME = "module_audit_checkpoint.json"
        const val SOFTWARE_KEY_FILE_NAME = "module_audit_emergency_key.json"
        const val LEGACY_ENVELOPE_SCHEMA_VERSION = 1
        const val ENVELOPE_SCHEMA_VERSION = 2
        const val SOFTWARE_KEY_SCHEMA_VERSION = 1
        const val LEGACY_CHECKPOINT_SCHEMA_VERSION = 2
        const val CHECKPOINT_SCHEMA_VERSION = 3
        const val AUTHORIZATION_SCHEMA_VERSION = 1
        const val AUTHORIZATION_NONCE_BYTES = 32
        const val P256_COORDINATE_BYTES = 32
        const val UNCOMPRESSED_EC_POINT: Byte = 0x04
    }
}
