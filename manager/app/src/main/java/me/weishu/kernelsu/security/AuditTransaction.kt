package me.weishu.kernelsu.security

import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import org.json.JSONArray
import org.json.JSONObject

enum class AuditTransactionState(val wireName: String) {
    Committed("committed");

    companion object {
        fun fromWireName(value: String): AuditTransactionState =
            entries.firstOrNull { it.wireName == value }
                ?: error("Unsupported audit transaction state: $value")
    }
}

data class AuditTransactionReceipt(
    val schemaVersion: Int,
    val operationId: String,
    val action: String,
    val state: AuditTransactionState,
    val replayed: Boolean,
    val targets: List<String>,
    val baseInventoryHash: String,
    val committedStoreRevision: String,
    val committedInventoryHash: String,
)

fun parseAuditTransactionReceipt(commandOutput: String): AuditTransactionReceipt {
    val transaction = JSONObject(commandOutput).getJSONObject("transaction")
    val receipt = AuditTransactionReceipt(
        schemaVersion = transaction.getInt("schema_version"),
        operationId = transaction.getString("operation_id"),
        action = transaction.getString("action"),
        state = AuditTransactionState.fromWireName(transaction.getString("state")),
        replayed = transaction.getBoolean("replayed"),
        targets = transaction.getJSONArray("targets").toStringList(),
        baseInventoryHash = transaction.getString("base_inventory_hash"),
        committedStoreRevision = transaction.getString("committed_store_revision"),
        committedInventoryHash = transaction.getString("committed_inventory_hash"),
    )
    check(receipt.schemaVersion == 1) { "Unsupported audit transaction receipt schema" }
    check(receipt.state == AuditTransactionState.Committed) {
        "Audit transaction did not commit"
    }
    check(receipt.operationId.isSha256Hex()) { "Invalid audit transaction operation id" }
    check(receipt.baseInventoryHash.isSha256Hex()) {
        "Invalid audit transaction base inventory"
    }
    check(receipt.committedStoreRevision.isSha256Hex()) {
        "Invalid committed audit store revision"
    }
    check(receipt.committedInventoryHash.isSha256Hex()) {
        "Invalid committed audit inventory"
    }
    return receipt
}

/** Notifies independent readers that a ksud audit transaction committed. */
object AuditTransactionCommits {
    private val mutableCommits = MutableSharedFlow<AuditTransactionReceipt>(
        extraBufferCapacity = 16,
    )
    val commits = mutableCommits.asSharedFlow()

    suspend fun publish(receipt: AuditTransactionReceipt) {
        mutableCommits.emit(receipt)
    }
}

private fun String.isSha256Hex(): Boolean =
    length == 64 && all { it in '0'..'9' || it in 'a'..'f' }

private fun JSONArray.toStringList(): List<String> =
    (0 until length()).map(::getString)
