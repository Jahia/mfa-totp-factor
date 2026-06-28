package org.jahia.modules.upa.mfa.extensions;

import org.osgi.service.component.annotations.Component;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * A small in-memory throttle for the locked-out "request MFA reset" flow: at most one request per
 * subject (keyed by user id) within a sliding window. Keeps a stuck or malicious user from spamming
 * the configured administrators with notification emails. In-memory on purpose — the throttle is a
 * convenience guard, not a security control (the request reveals nothing and the actual reset is
 * admin-gated), so it need not survive a restart or coordinate across a cluster.
 */
@Component(service = MfaResetRequestRateLimiter.class, immediate = true)
public class MfaResetRequestRateLimiter {

    /** One reset request per user per 10 minutes. */
    static final long WINDOW_MILLIS = TimeUnit.MINUTES.toMillis(10);

    private final Map<String, Long> lastRequestMillis = new ConcurrentHashMap<>();

    /** Pure window check (unit-tested): a request is allowed when none is recorded or the window elapsed. */
    public static boolean allowed(Long lastMillis, long now) {
        return lastMillis == null || (now - lastMillis) >= WINDOW_MILLIS;
    }

    /**
     * Atomically record a request for {@code key} when the window allows it.
     *
     * @return true when the request is permitted (and recorded); false when still inside the window.
     */
    public boolean tryAcquire(String key) {
        long now = System.currentTimeMillis();
        AtomicBoolean acquired = new AtomicBoolean(false);
        lastRequestMillis.compute(key, (k, prev) -> {
            if (allowed(prev, now)) {
                acquired.set(true);
                return now;
            }
            return prev;
        });
        return acquired.get();
    }
}
