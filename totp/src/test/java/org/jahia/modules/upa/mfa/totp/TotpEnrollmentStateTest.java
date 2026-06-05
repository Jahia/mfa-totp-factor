package org.jahia.modules.upa.mfa.totp;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Verifies that the in-session enrollment secret carries a TTL so an abandoned enrollment
 * does not leave the Base32 secret hanging in HTTP session storage forever.
 */
public class TotpEnrollmentStateTest {

    @Test
    public void freshState_isNotExpired() {
        TotpEnrollmentState s = new TotpEnrollmentState("JBSWY3DPEHPK3PXP");
        assertFalse(s.isExpired());
    }

    @Test
    public void stateOlderThanTtl_isExpired() {
        long stale = System.currentTimeMillis() - TotpEnrollmentState.TTL_MILLIS - 1_000L;
        TotpEnrollmentState s = new TotpEnrollmentState("JBSWY3DPEHPK3PXP", stale);
        assertTrue(s.isExpired());
    }
}
