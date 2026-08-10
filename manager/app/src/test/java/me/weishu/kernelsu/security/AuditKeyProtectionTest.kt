package me.weishu.kernelsu.security

import kotlin.test.Test
import kotlin.test.assertFailsWith

class AuditKeyProtectionTest {
    @Test
    fun hardwareProtectionCannotSilentlyDowngrade() {
        assertFailsWith<IllegalStateException> {
            validateAuditKeyProtectionTransition(
                AuditKeyProtection.Hardware,
                AuditKeyProtection.Degraded,
            )
        }
        assertFailsWith<IllegalStateException> {
            validateAuditKeyProtectionTransition(
                AuditKeyProtection.Hardware,
                AuditKeyProtection.Emergency,
            )
        }
    }

    @Test
    fun degradedProtectionMayUpgradeToHardware() {
        validateAuditKeyProtectionTransition(
            AuditKeyProtection.Degraded,
            AuditKeyProtection.Hardware,
        )
    }

    @Test
    fun emergencyBackendCannotChangeUnderExistingCheckpoint() {
        assertFailsWith<IllegalStateException> {
            validateAuditKeyProtectionTransition(
                AuditKeyProtection.Emergency,
                AuditKeyProtection.Hardware,
            )
        }
    }

    @Test
    fun degradedProtectionCannotFallBackWithoutNewEnrollment() {
        assertFailsWith<IllegalStateException> {
            validateAuditKeyProtectionTransition(
                AuditKeyProtection.Degraded,
                AuditKeyProtection.Emergency,
            )
        }
    }
}
