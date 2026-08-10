package me.weishu.kernelsu.security

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AuditChainRecoveryTest {
    @Test
    fun acceptsVerifiedPrefixSealedByIntegrityIncident() {
        assertTrue(rebuild(previous = listOf("a", "b", "c"), current = listOf("a", "incident")))
    }

    @Test
    fun acceptsAuthenticatedHeadLossIncident() {
        assertTrue(
            rebuild(
                previous = listOf("a", "b", "c"),
                current = listOf("a", "b", "incident"),
                corruptedFrom = 0L,
            )
        )
    }

    @Test
    fun rejectsChangedPrefixAndUnsealedRollback() {
        assertFalse(rebuild(previous = listOf("a", "b"), current = listOf("x", "incident")))
        assertFalse(
            rebuild(
                previous = listOf("a", "b"),
                current = listOf("a", "replacement"),
                kind = "installed_rescan",
            )
        )
    }

    @Test
    fun rejectsMissingHistoryAndEventsAfterIncident() {
        assertFalse(rebuild(previous = listOf("a", "b"), current = emptyList()))
        assertFalse(
            rebuild(
                previous = listOf("a", "b", "c"),
                current = listOf("a", "incident", "extra"),
                lastPreviousHash = "incident",
                lastSequence = 3L,
            )
        )
    }

    @Test
    fun requiresHighRiskAndHmacVerification() {
        assertFalse(
            rebuild(
                previous = listOf("a", "b"),
                current = listOf("a", "incident"),
                highRisk = false,
            )
        )
        assertFalse(
            rebuild(
                previous = listOf("a", "b"),
                current = listOf("a", "incident"),
                hmacVerified = false,
            )
        )
    }

    private fun rebuild(
        previous: List<String>,
        current: List<String>,
        highRisk: Boolean = true,
        hmacVerified: Boolean = true,
        kind: String = "integrity_incident",
        corruptedFrom: Long = 2L,
        lastPreviousHash: String = current.dropLast(1).lastOrNull() ?: AUDIT_GENESIS,
        lastSequence: Long = current.size.toLong(),
    ): Boolean = isAuthenticatedAuditChainRebuild(
        previousHashes = previous,
        currentHashes = current,
        currentHighRisk = highRisk,
        hmacVerified = hmacVerified,
        eventCount = current.size.toLong(),
        lastSequence = lastSequence,
        lastPreviousHash = lastPreviousHash,
        lastKind = kind,
        corruptedFromSequence = corruptedFrom,
        reason = "event authentication mismatch",
        quarantine = "/data/adb/ksu/module_audit/modules/test/quarantine/incident",
    )

    private companion object {
        const val AUDIT_GENESIS =
            "0000000000000000000000000000000000000000000000000000000000000000"
    }
}
