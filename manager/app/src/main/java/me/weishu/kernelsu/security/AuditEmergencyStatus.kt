package me.weishu.kernelsu.security

import org.json.JSONArray
import org.json.JSONObject

data class AuditEmergencyStatus(
    val active: Boolean,
    val phase: String,
    val reason: String,
    val detail: String,
    val affectedModuleIds: List<String>,
    val scriptQuarantineRoot: String,
    val scriptQuarantines: List<AuditEmergencyScriptQuarantine>,
    val containmentFailures: List<String>,
    val recoveryCondition: String,
    val triggeredAtUnixSeconds: Long,
    val updatedAtUnixSeconds: Long,
)

data class AuditEmergencyScriptQuarantine(
    val sessionPath: String,
    val entries: List<AuditEmergencyScriptQuarantineEntry>,
)

data class AuditEmergencyScriptQuarantineEntry(
    val sourcePath: String,
    val quarantinePath: String,
    val state: String,
    val error: String?,
)

data class ModuleAuditResponseStatus(
    val kernelSafeMode: Boolean,
    val emergency: AuditEmergencyStatus?,
)

fun parseModuleAuditResponseStatus(raw: String): ModuleAuditResponseStatus {
    val root = JSONObject(raw)
    check(root.has("emergency")) {
        "ksud does not expose module audit emergency state"
    }
    val emergency = root.optJSONObject("emergency")?.let { value ->
        check(value.getInt("schema_version") == AUDIT_EMERGENCY_SCHEMA_VERSION) {
            "Unsupported module audit emergency status schema"
        }
        AuditEmergencyStatus(
            active = value.getBoolean("active"),
            phase = value.getString("phase"),
            reason = value.getString("reason"),
            detail = value.getString("detail"),
            affectedModuleIds = value.getJSONArray("affected_module_ids").strings(),
            scriptQuarantineRoot = value.getString("script_quarantine_root"),
            scriptQuarantines = value.optJSONArray("script_quarantines")?.objects()?.map {
                AuditEmergencyScriptQuarantine(
                    sessionPath = it.getString("session_path"),
                    entries = it.getJSONArray("entries").objects().map { entry ->
                        AuditEmergencyScriptQuarantineEntry(
                            sourcePath = entry.getString("source_path"),
                            quarantinePath = entry.getString("quarantine_path"),
                            state = entry.getString("state"),
                            error = entry.nullableString("error"),
                        )
                    },
                )
            }.orEmpty(),
            containmentFailures = value.getJSONArray("containment_failures").strings(),
            recoveryCondition = value.getString("recovery_condition"),
            triggeredAtUnixSeconds = value.getLong("triggered_at_unix_seconds"),
            updatedAtUnixSeconds = value.getLong("updated_at_unix_seconds"),
        )
    }
    return ModuleAuditResponseStatus(
        kernelSafeMode = root.getBoolean("kernel_safe_mode"),
        emergency = emergency,
    )
}

private fun JSONArray.strings(): List<String> = buildList {
    for (index in 0 until length()) add(getString(index))
}

private fun JSONArray.objects(): List<JSONObject> = buildList {
    for (index in 0 until length()) add(getJSONObject(index))
}

private fun JSONObject.nullableString(name: String): String? =
    if (!has(name) || isNull(name)) null else optString(name).takeIf(String::isNotBlank)

private const val AUDIT_EMERGENCY_SCHEMA_VERSION = 1
