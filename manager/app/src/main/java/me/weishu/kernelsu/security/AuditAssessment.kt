package me.weishu.kernelsu.security

import org.json.JSONArray
import org.json.JSONObject

data class AuditRecoveryRoute(
    val action: String,
    val available: Boolean,
    val ready: Boolean,
    val destructive: Boolean,
    val conditions: List<AuditRecoveryCondition>,
)

data class AuditRecoveryCondition(
    val kind: String,
    val state: String,
)

enum class AuditModuleDisposition(val wireName: String) {
    Trusted("trusted"),
    ContainmentRequired("containment_required"),
    SecureRemovalRequired("secure_removal_required"),
    SealedRecoveryRequired("sealed_recovery_required");

    companion object {
        fun fromWireName(value: String): AuditModuleDisposition =
            entries.firstOrNull { it.wireName == value }
                ?: error("Unsupported audit module disposition: $value")
    }
}

data class AuditModuleAssessment(
    val moduleId: String,
    val disposition: AuditModuleDisposition,
    val containmentState: String?,
    val actions: List<AuditRecoveryRoute>,
) {
    private fun action(name: String): AuditRecoveryRoute? = actions.firstOrNull { it.action == name }

    val secureRemovalRoute: AuditRecoveryRoute?
        get() = action("secure_remove_module")
}

data class AuditAssessment(
    val schemaVersion: Int,
    val snapshotRevision: String,
    val inventoryHash: String,
    val inventoryRelation: AuditInventoryRelation,
    val kernelSafeMode: Boolean,
    val authorizationConfigured: Boolean,
    val modules: List<AuditModuleAssessment>,
    val staleModuleIds: List<String>,
    val sealedRecoveryModuleIds: List<String>,
    val unauditedModuleIds: List<String>,
    val unsealedModuleIds: List<String>,
) {
    fun module(moduleId: String): AuditModuleAssessment? =
        modules.firstOrNull { it.moduleId == moduleId }
}

fun parseAuditAssessment(raw: String): AuditAssessment = parseAuditAssessment(JSONObject(raw))

fun parseAuditAssessment(value: JSONObject): AuditAssessment {
    check(value.getInt("schema_version") == 1) {
        "Unsupported audit assessment schema"
    }
    return AuditAssessment(
        schemaVersion = value.getInt("schema_version"),
        snapshotRevision = value.getString("snapshot_revision"),
        inventoryHash = value.getString("inventory_hash"),
        inventoryRelation = AuditInventoryRelation.fromWireName(
            value.getString("inventory_relation")
        ),
        kernelSafeMode = value.getBoolean("kernel_safe_mode"),
        authorizationConfigured = value.getBoolean("authorization_configured"),
        modules = value.getJSONArray("modules").objects().map { module ->
            AuditModuleAssessment(
                moduleId = module.getString("module_id"),
                disposition = AuditModuleDisposition.fromWireName(
                    module.getString("disposition")
                ),
                containmentState = module.nullableString("containment_state"),
                actions = parseAuditRecoveryRoutes(module.optJSONArray("actions")),
            )
        },
        staleModuleIds = value.getJSONArray("stale_module_ids").strings(),
        sealedRecoveryModuleIds = value.getJSONArray("sealed_recovery_module_ids").strings(),
        unauditedModuleIds = value.getJSONArray("unaudited_module_ids").strings(),
        unsealedModuleIds = value.getJSONArray("unsealed_module_ids").strings(),
    )
}

fun parseAuditRecoveryRoutes(value: JSONArray?): List<AuditRecoveryRoute> =
    value?.objects()?.map { route ->
        AuditRecoveryRoute(
            action = route.getString("action"),
            available = route.getBoolean("available"),
            ready = route.optBoolean("ready", false),
            destructive = route.getBoolean("destructive"),
            conditions = route.optJSONArray("conditions")?.objects()?.map { condition ->
                AuditRecoveryCondition(
                    kind = condition.getString("kind"),
                    state = condition.getString("state"),
                )
            }.orEmpty(),
        )
    }.orEmpty()

private fun JSONArray.strings(): List<String> = buildList {
    for (index in 0 until length()) add(getString(index))
}

private fun JSONArray.objects(): List<JSONObject> = buildList {
    for (index in 0 until length()) add(getJSONObject(index))
}

private fun JSONObject.nullableString(name: String): String? =
    if (!has(name) || isNull(name)) null else optString(name).takeIf(String::isNotBlank)
