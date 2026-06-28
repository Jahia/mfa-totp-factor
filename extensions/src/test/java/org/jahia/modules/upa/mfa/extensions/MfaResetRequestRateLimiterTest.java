package org.jahia.modules.upa.mfa.extensions;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * The reset-request throttle: one request per subject per window. The window arithmetic is pure
 * (unit-tested here); the per-key recording is exercised through {@link MfaResetRequestRateLimiter#tryAcquire}.
 */
public class MfaResetRequestRateLimiterTest {

    @Test
    public void allowedWhenNoPriorRequest() {
        assertTrue(MfaResetRequestRateLimiter.allowed(null, 1_000L));
    }

    @Test
    public void throttledInsideWindowAllowedAfter() {
        long start = 1_000L;
        assertFalse(MfaResetRequestRateLimiter.allowed(start, start + 1));
        assertFalse(MfaResetRequestRateLimiter.allowed(start,
                start + MfaResetRequestRateLimiter.WINDOW_MILLIS - 1));
        assertTrue(MfaResetRequestRateLimiter.allowed(start,
                start + MfaResetRequestRateLimiter.WINDOW_MILLIS));
    }

    @Test
    public void tryAcquireGrantsOncePerKeyThenThrottles() {
        MfaResetRequestRateLimiter limiter = new MfaResetRequestRateLimiter();
        assertTrue("first request for alice is allowed", limiter.tryAcquire("alice"));
        assertFalse("second request for alice within the window is throttled", limiter.tryAcquire("alice"));
        // A different subject is independent.
        assertTrue("first request for bob is allowed", limiter.tryAcquire("bob"));
    }
}
