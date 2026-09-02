package me.weishu.kernelsu.security

import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AuditSealTransitionTest {
    @Test
    fun currentSealNeedsNoWrite() {
        assertFalse(
            requiresAuditSealCommit(
                configured = true,
                sealedHash = "current",
                currentHash = "current",
                previousHash = "previous",
            )
        )
    }

    @Test
    fun initializedCheckpointMayCreateItsFirstSeal() {
        assertTrue(
            requiresAuditSealCommit(
                configured = false,
                sealedHash = null,
                currentHash = "current",
                previousHash = null,
            )
        )
    }

    @Test
    fun verifiedExtensionMayReplaceExactlyThePreviousSeal() {
        assertTrue(
            requiresAuditSealCommit(
                configured = true,
                sealedHash = "previous",
                currentHash = "current",
                previousHash = "previous",
            )
        )
    }

    @Test
    fun missingStableSealCanBeRecoveredButTransitionAndRollbackAreRejected() {
        assertTrue(
            requiresAuditSealCommit(
                configured = false,
                sealedHash = null,
                currentHash = "current",
                previousHash = "current",
            )
        )
        assertFailsWith<IllegalStateException> {
            requiresAuditSealCommit(
                configured = false,
                sealedHash = null,
                currentHash = "current",
                previousHash = "previous",
            )
        }
        assertFailsWith<IllegalStateException> {
            requiresAuditSealCommit(
                configured = true,
                sealedHash = "unexpected",
                currentHash = "current",
                previousHash = "previous",
            )
        }
    }

    @Test
    fun persistedTransitionSelectsTheSealThatKsudActuallyAcknowledged() {
        assertTrue(
            selectAuditTransitionBaseHash(
                sealedHash = "current",
                currentHash = "current",
                previousHash = "previous",
            ) == "current"
        )
        assertTrue(
            selectAuditTransitionBaseHash(
                sealedHash = "previous",
                currentHash = "current",
                previousHash = "previous",
            ) == "previous"
        )
        assertFailsWith<IllegalStateException> {
            selectAuditTransitionBaseHash(
                sealedHash = "replayed",
                currentHash = "current",
                previousHash = "previous",
            )
        }
    }
}
