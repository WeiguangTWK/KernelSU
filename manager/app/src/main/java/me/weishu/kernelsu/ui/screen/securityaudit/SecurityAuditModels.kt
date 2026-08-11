package me.weishu.kernelsu.ui.screen.securityaudit

import me.weishu.kernelsu.security.AuditKeyProtection
import org.json.JSONArray
import org.json.JSONObject

data class AuditHistory(
    val status: AuditStatus,
    val events: List<AuditEvent> = emptyList(),
    val integrityError: String? = null,
)

data class AuditStatus(
    val moduleId: String,
    val verification: String,
    val highRisk: Boolean,
    val unresolvedRisk: Boolean,
    val eventCount: Int,
    val headHash: String,
    val hmacVerified: Boolean,
    val managerCheckpoint: String,
    val containmentState: String? = null,
    val quarantinedPersistentScripts: Int = 0,
    val persistentScriptOwnership: String? = null,
)

enum class SecureRemovalPhase {
    RecoveringAudit,
    AnchoringAudit,
    RemovingModule,
    RefreshingModules,
    Completed,
}

data class AuditEvent(
    val schemaVersion: Int,
    val moduleId: String,
    val sequence: Long,
    val timestampUnixSeconds: Long,
    val previousHash: String,
    val kind: AuditEventKind,
)

data class AuditEventKind(
    val type: String,
    val attemptId: String? = null,
    val outcome: String? = null,
    val error: String? = null,
    val report: AuditReport? = null,
    val corruptedFromSequence: Long? = null,
    val reason: String? = null,
    val quarantine: String? = null,
    val operationId: String? = null,
    val removedPaths: List<String> = emptyList(),
)

data class AuditReport(
    val schemaVersion: Int,
    val packageSha256: String,
    val moduleId: String? = null,
    val findings: List<AuditFinding> = emptyList(),
    val scannedFiles: Int,
    val derivedArtifacts: Int,
)

data class AuditFinding(
    val ruleId: String,
    val severity: String,
    val path: String,
    val line: Int? = null,
    val title: String,
    val evidence: String,
    val provenance: List<String> = emptyList(),
)

data class SecurityAuditUiState(
    val isLoading: Boolean = true,
    val isRefreshing: Boolean = false,
    val isRescanning: Boolean = false,
    val isPruning: Boolean = false,
    val isRecovering: Boolean = false,
    val secureRemovalModuleId: String? = null,
    val secureRemovalPhase: SecureRemovalPhase? = null,
    val histories: List<AuditHistory> = emptyList(),
    val staleModuleIds: List<String> = emptyList(),
    val checkpointCompromised: Boolean = false,
    val checkpointIncident: String? = null,
    val recoverableModuleIds: List<String> = emptyList(),
    val sealedRecoveryModuleIds: List<String> = emptyList(),
    val recoverySafeMode: Boolean = false,
    val keyProtection: AuditKeyProtection = AuditKeyProtection.Unavailable,
    val auditAuthorizationReady: Boolean = false,
    val errorMessage: String? = null,
) {
    val auditMutationBlocked: Boolean
        get() =
            checkpointCompromised || !auditAuthorizationReady || isLoading || isRefreshing ||
                isRecovering || secureRemovalInProgress

    val secureRemovalInProgress: Boolean
        get() = secureRemovalPhase != null && secureRemovalPhase != SecureRemovalPhase.Completed

    val highRiskModules: Int
        get() = histories.count { it.isHighRisk() }

    val networkModules: Int
        get() = histories.countRules("KSU-AUDIT-NET-")

    val binaryModules: Int
        get() = histories.countRules("KSU-AUDIT-BIN-")

    val persistentScriptModules: Int
        get() = histories.countRules("KSU-AUDIT-PERSIST-")

    val findingCount: Int
        get() = histories.sumOf { history ->
            history.events.sumOf { it.kind.report?.findings?.size ?: 0 }
        }

    val interruptedInstalls: Int
        get() = histories.sumOf { history ->
            val accepted = history.events
                .filter { it.kind.type == "install_accepted" }
                .mapNotNull { it.kind.attemptId }
                .toSet()
            val completed = history.events
                .filter { it.kind.type == "install_result" }
                .mapNotNull { it.kind.attemptId }
                .toSet()
            (accepted - completed).size
        }
}

enum class AuditCategory(val key: String) {
    CriticalRisk("critical_risk"),
    PersistentScripts("persistent_scripts"),
    ExternalFilesystem("external_filesystem"),
    PartitionWrites("partition_writes"),
    DestructiveDeletes("destructive_deletes"),
    Network("network"),
    PrebuiltBinaries("prebuilt_binaries"),
    PackedContent("packed_content"),
    ModuleScripts("module_scripts"),
    ArchiveSafety("archive_safety"),
    ModuleCleanup("module_cleanup"),
    Other("other");

    companion object {
        fun fromKey(key: String): AuditCategory = entries.firstOrNull { it.key == key } ?: Other
    }
}

data class AuditCategoryGroup(
    val category: AuditCategory,
    val findings: List<AuditFinding>,
)

private fun List<AuditHistory>.countRules(prefix: String): Int = count { history ->
    history.latestReport()?.findings?.any { finding -> finding.ruleId.startsWith(prefix) } == true
}

fun AuditHistory.latestReport(): AuditReport? = events
    .asReversed()
    .firstNotNullOfOrNull { it.kind.report }

fun AuditHistory.displayName(): String = latestReport()?.moduleId ?: status.moduleId

fun AuditHistory.packageFingerprint(): String? = latestReport()?.packageSha256?.take(12)

fun AuditHistory.isHighRisk(): Boolean = status.unresolvedRisk || latestFindings().any {
    it.severity == "critical"
}

fun AuditHistory.categoryGroups(): List<AuditCategoryGroup> = findingsForDetails()
    .groupBy { it.auditCategory() }
    .map { (category, findings) -> AuditCategoryGroup(category, findings) }
    .sortedBy { it.category.ordinal }

private fun AuditHistory.findingsForDetails(): List<AuditFinding> {
    val latest = latestFindings()
    if (!status.unresolvedRisk) return latest
    val lastRemovalSequence = events
        .lastOrNull { it.kind.type == "secure_removal_completed" }
        ?.sequence
        ?: 0L
    val unresolvedCritical = events
        .asReversed()
        .firstNotNullOfOrNull { event ->
            event.kind.report
                ?.takeIf { event.sequence > lastRemovalSequence }
                ?.findings
                ?.filter { it.severity == "critical" }
                ?.takeIf { it.isNotEmpty() }
        }
        .orEmpty()
    return (latest + unresolvedCritical).distinctBy {
        listOf(it.ruleId, it.path, it.line?.toString().orEmpty(), it.evidence)
    }
}

fun AuditHistory.hasCategory(category: AuditCategory): Boolean =
    if (category == AuditCategory.CriticalRisk) {
        isHighRisk()
    } else {
        latestFindings().any { it.auditCategory() == category }
    }

fun AuditFinding.auditCategory(): AuditCategory = when {
    ruleId.startsWith("KSU-AUDIT-FIN-") -> AuditCategory.CriticalRisk
    ruleId.startsWith("KSU-AUDIT-PRIV-") -> AuditCategory.CriticalRisk
    ruleId.startsWith("KSU-AUDIT-APK-") -> AuditCategory.PrebuiltBinaries
    ruleId.startsWith("KSU-AUDIT-ZYGISK-") -> AuditCategory.PrebuiltBinaries
    ruleId.startsWith("KSU-AUDIT-PERSIST-") -> AuditCategory.PersistentScripts
    ruleId == "KSU-AUDIT-FS-001" || ruleId == "KSU-AUDIT-FS-003" -> AuditCategory.PartitionWrites
    ruleId == "KSU-AUDIT-FS-002" -> AuditCategory.ExternalFilesystem
    ruleId == "KSU-AUDIT-FS-010" || ruleId == "KSU-AUDIT-FS-012" -> AuditCategory.DestructiveDeletes
    ruleId == "KSU-AUDIT-FS-011" -> AuditCategory.ModuleCleanup
    ruleId.startsWith("KSU-AUDIT-NET-") -> AuditCategory.Network
    ruleId.startsWith("KSU-AUDIT-BIN-") -> AuditCategory.PrebuiltBinaries
    ruleId.startsWith("KSU-AUDIT-PACK-") -> AuditCategory.PackedContent
    ruleId.startsWith("KSU-AUDIT-SCRIPT-") -> AuditCategory.ModuleScripts
    ruleId.startsWith("KSU-AUDIT-ZIP-") -> AuditCategory.ArchiveSafety
    else -> AuditCategory.Other
}

fun parseAuditHistories(raw: String): List<AuditHistory> = JSONArray(raw).mapObjects { history ->
    val status = history.getJSONObject("status")
    AuditHistory(
        status = AuditStatus(
            moduleId = status.getString("module_id"),
            verification = status.getString("verification"),
            highRisk = status.getBoolean("high_risk"),
            unresolvedRisk = status.getBoolean("unresolved_risk"),
            eventCount = status.getInt("event_count"),
            headHash = status.getString("head_hash"),
            hmacVerified = status.getBoolean("hmac_verified"),
            managerCheckpoint = status.getString("manager_checkpoint"),
            containmentState = status.optString("containment_state").takeIf(String::isNotBlank),
            quarantinedPersistentScripts = status.optInt("quarantined_persistent_scripts"),
            persistentScriptOwnership = status.optString("persistent_script_ownership").takeIf(String::isNotBlank),
        ),
        events = history.optJSONArray("events")?.mapObjects(::parseAuditEvent).orEmpty(),
        integrityError = history.optString("integrity_error").takeIf(String::isNotBlank),
    )
}

fun parseStaleAuditModuleIds(raw: String): List<String> = JSONArray(raw)
    .mapObjects { entry -> entry.getString("module_id") }

private fun parseAuditEvent(event: JSONObject): AuditEvent {
    val kind = event.getJSONObject("kind")
    return AuditEvent(
        schemaVersion = event.getInt("schema_version"),
        moduleId = event.getString("module_id"),
        sequence = event.getLong("sequence"),
        timestampUnixSeconds = event.getLong("timestamp_unix_seconds"),
        previousHash = event.getString("previous_hash"),
        kind = AuditEventKind(
            type = kind.getString("type"),
            attemptId = kind.nullableString("attempt_id"),
            outcome = kind.nullableString("outcome"),
            error = kind.nullableString("error"),
            report = kind.optJSONObject("report")?.let(::parseAuditReport),
            corruptedFromSequence = kind.optLongOrNull("corrupted_from_sequence"),
            reason = kind.nullableString("reason"),
            quarantine = kind.nullableString("quarantine"),
            operationId = kind.nullableString("operation_id"),
            removedPaths = kind.optJSONArray("removed_paths")?.mapStrings().orEmpty(),
        ),
    )
}

private fun parseAuditReport(report: JSONObject): AuditReport = AuditReport(
    schemaVersion = report.getInt("schema_version"),
    packageSha256 = report.getString("package_sha256"),
    moduleId = report.nullableString("module_id"),
    findings = report.optJSONArray("findings")?.mapObjects { finding ->
        AuditFinding(
            ruleId = finding.getString("rule_id"),
            severity = finding.getString("severity"),
            path = finding.getString("path"),
            line = finding.optIntOrNull("line"),
            title = finding.getString("title"),
            evidence = finding.getString("evidence"),
            provenance = finding.optJSONArray("provenance")?.mapStrings().orEmpty(),
        )
    }.orEmpty(),
    scannedFiles = report.getInt("scanned_files"),
    derivedArtifacts = report.getInt("derived_artifacts"),
)

private inline fun <T> JSONArray.mapObjects(transform: (JSONObject) -> T): List<T> =
    List(length()) { index -> transform(getJSONObject(index)) }

private fun JSONArray.mapStrings(): List<String> = List(length()) { index -> getString(index) }

private fun JSONObject.nullableString(name: String): String? =
    if (isNull(name) || !has(name)) null else getString(name)

private fun JSONObject.optIntOrNull(name: String): Int? =
    if (isNull(name) || !has(name)) null else getInt(name)

private fun JSONObject.optLongOrNull(name: String): Long? =
    if (isNull(name) || !has(name)) null else getLong(name)
