package org.jahia.modules.upa.mfa.totp;

import org.junit.Test;

import static org.jahia.modules.upa.mfa.totp.TotpManagementRateLimiter.MAX_FAILURES;
import static org.jahia.modules.upa.mfa.totp.TotpManagementRateLimiter.WINDOW_MILLIS;
import static org.jahia.modules.upa.mfa.totp.TotpManagementRateLimiter.afterFailure;
import static org.jahia.modules.upa.mfa.totp.TotpManagementRateLimiter.lockedNow;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Verifies the pure window/counter arithmetic of the management-mutation rate limiter.
 * The JCR persistence layer (cluster-safe lockout state) is exercised end-to-end by the
 * Cypress suite; here we pin the sliding-window decision logic.
 */
public class TotpManagementRateLimiterTest {

    private static final long T0 = 1_000_000_000L;

    @Test
    public void zeroFailuresIsNotLocked() {
        assertFalse(lockedNow(0L, 0L, T0));
    }

    @Test
    public void locksOutAtMaxFailuresWithinWindow() {
        assertFalse("one below the threshold is not locked", lockedNow(MAX_FAILURES - 1, T0, T0 + 1000));
        assertTrue("at the threshold the user is locked", lockedNow(MAX_FAILURES, T0, T0 + 1000));
    }

    @Test
    public void notLockedOnceWindowElapses() {
        long afterWindow = T0 + WINDOW_MILLIS + 1;
        assertFalse("an elapsed window clears the lockout", lockedNow(MAX_FAILURES, T0, afterWindow));
    }

    @Test
    public void firstFailureOpensAFreshWindow() {
        long[] next = afterFailure(0L, 0L, T0);
        assertEquals("failure count starts at 1", 1L, next[0]);
        assertEquals("window starts now", T0, next[1]);
    }

    @Test
    public void subsequentFailureWithinWindowIncrementsAndKeepsWindow() {
        long[] next = afterFailure(2L, T0, T0 + 5000);
        assertEquals(3L, next[0]);
        assertEquals("window start is preserved within the window", T0, next[1]);
    }

    @Test
    public void failureAfterWindowResetsToFreshWindow() {
        long late = T0 + WINDOW_MILLIS + 1;
        long[] next = afterFailure(4L, T0, late);
        assertEquals("counter resets after the window elapses", 1L, next[0]);
        assertEquals("a new window opens", late, next[1]);
    }
}
