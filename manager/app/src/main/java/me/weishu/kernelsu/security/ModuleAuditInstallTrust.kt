package me.weishu.kernelsu.security

import me.weishu.kernelsu.ksuApp
import me.weishu.kernelsu.ui.util.commitModuleAuditSeal
import me.weishu.kernelsu.ui.util.registerModuleAuditAuthorizationKey
import me.weishu.kernelsu.ui.util.streamModuleAuditDashboard
import org.json.JSONArray
import org.json.JSONObject

data class ModuleAuditInstallTrust(
    val releasableModuleIds: Set<String>,
)

suspend fun sealModuleAuditSession(installSession: String): ModuleAuditInstallTrust {
    val histories = linkedMapOf<String, JSONObject>()
    var completion: JSONObject? = null
    streamModuleAuditDashboard(installSession) { rawLine ->
        val line = JSONObject(rawLine)
        when (line.getString("type")) {
            "module" -> histories[line.getString("module_id")] = line.getJSONObject("history")
            "error" -> error(line.optString("error", "Module audit verification failed"))
            "complete" -> completion = line
        }
    }

    val completed = checkNotNull(completion) { "Module audit verification did not complete" }
    check(!completed.optBoolean("uninitialized", false)) {
        "Module audit store remained uninitialized after installation"
    }
    val inventoryRelation = AuditInventoryRelation.fromWireName(
        completed.getString("inventory_relation")
    )
    check(inventoryRelation != AuditInventoryRelation.SealedDamage) {
        "Module audit installation session produced sealed inventory damage"
    }
    val store = ModuleAuditCheckpointStore(ksuApp)
    val sealStatus = completed.getJSONObject("seal_status")
    val checkpoint = store.reconcile(
        completed.getJSONObject("checkpoint").toString(),
        JSONArray(histories.values).toString(),
        sealStatus.nullableString("seal_hash"),
    )
    check(
        checkpoint.trust == AuditCheckpointTrust.Initialized ||
            checkpoint.trust == AuditCheckpointTrust.Verified
    ) { checkpoint.detail ?: "Manager rejected the installed module audit transition" }
    check(checkpoint.recoverableModules.isEmpty()) {
        "Installed module audit transition requires explicit recovery"
    }

    val publicKey = store.authorizationPublicKeyHex()
    val ownKeyId = store.authorizationKeyId()
    val authorizationStatus = completed.getJSONObject("authorization_status")
    if (!authorizationStatus.optBoolean("configured", false)) {
        val registered = JSONObject(
            registerModuleAuditAuthorizationKey(publicKey, recover = false)
        )
        check(registered.optString("key_id") == ownKeyId) {
            "ksud registered an unexpected Manager audit authorization key"
        }
    } else {
        check(authorizationStatus.optString("key_id") == ownKeyId) {
            "Manager audit authorization identity changed"
        }
    }

    val configured = sealStatus.optBoolean("configured", false)
    val sealedHash = sealStatus.nullableString("seal_hash")
    val currentHash = store.currentSealHash()
    if (requiresAuditSealCommit(
            configured,
            sealedHash,
            currentHash,
            store.acceptablePreviousSealHash(),
        )
    ) {
        val committed = JSONObject(commitModuleAuditSeal(store.currentSealEnvelopeHex()))
        check(committed.optBoolean("configured", false)) {
            "ksud did not persist the Manager audit seal"
        }
        check(committed.optString("seal_hash") == currentHash) {
            "ksud persisted an unexpected Manager audit seal"
        }
    }
    store.markSealSynchronized(currentHash)

    return ModuleAuditInstallTrust(
        releasableModuleIds = histories.values.mapNotNullTo(mutableSetOf()) { history ->
            val status = history.getJSONObject("status")
            status.getString("module_id").takeIf {
                !status.optBoolean("unresolved_risk", true) &&
                    status.nullableString("containment_state") == null
            }
        }
    )
}

private fun JSONObject.nullableString(name: String): String? =
    if (isNull(name)) null else optString(name).takeIf(String::isNotBlank)
