package org.jahia.modules.upa.mfa.totp;

import org.jahia.services.content.JCRTemplate;
import org.jahia.services.content.decorator.JCRUserNode;
import org.jahia.services.usermanager.JahiaUserManagerService;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jcr.RepositoryException;

/**
 * Per-user attempt counter that throttles TOTP code checks issued by the management GraphQL
 * mutations ({@code confirmEnroll}, {@code regenerateBackupCodes}, {@code disable}, and the
 * privileged {@code enroll(force=true)}).
 * <p>
 * The {@code verify} mutation is already protected by UPA's {@code MfaServiceImpl} lockout;
 * the management surface is protected here because it accepts a code without going through
 * {@code verifyFactor}.
 * <p>
 * State is persisted in shared JCR (the {@code upaTotp:lockout} mixin on the user node) rather
 * than an in-heap map, so the lockout is <b>cluster-safe</b> (an attacker cannot multiply the
 * budget by spreading attempts across cluster nodes) and <b>survives a restart</b>. The
 * management surface is low-volume, so a JCR write per failed attempt is acceptable. On a JCR
 * error the limiter fails open (does not block) — the underlying code check still has to pass,
 * so this only removes the extra throttle, never weakens the actual verification.
 */
@Component(service = TotpManagementRateLimiter.class, immediate = true)
public class TotpManagementRateLimiter {

    private static final Logger logger = LoggerFactory.getLogger(TotpManagementRateLimiter.class);

    /** Maximum failures within {@link #WINDOW_MILLIS} before the user is locked out. */
    public static final int MAX_FAILURES = 5;

    /** Sliding-window length: 10 minutes. */
    public static final long WINDOW_MILLIS = 10L * 60L * 1000L;

    static final String MIXIN_LOCKOUT = "upaTotp:lockout";
    static final String PROP_FAILED_ATTEMPTS = "upaTotp:failedAttempts";
    static final String PROP_WINDOW_START = "upaTotp:windowStart";

    private JahiaUserManagerService userManagerService;

    @Reference
    public void setUserManagerService(JahiaUserManagerService userManagerService) {
        this.userManagerService = userManagerService;
    }

    // --- Pure window arithmetic (unit-tested; the JCR plumbing below is covered by E2E) ---

    /** Whether the given counters represent a locked-out state at {@code now}. */
    static boolean lockedNow(long failures, long windowStart, long now) {
        if ((now - windowStart) > WINDOW_MILLIS) {
            return false; // window elapsed
        }
        return failures >= MAX_FAILURES;
    }

    /**
     * Compute the next {failures, windowStart} after recording a failure at {@code now}.
     * Opens a fresh window when there was no prior failure or the previous window elapsed.
     */
    static long[] afterFailure(long failures, long windowStart, long now) {
        if (failures == 0 || (now - windowStart) > WINDOW_MILLIS) {
            return new long[]{1L, now};
        }
        return new long[]{failures + 1, windowStart};
    }

    /**
     * Test whether the user is currently locked out from management TOTP checks.
     */
    public boolean isLockedOut(String userId) {
        if (userId == null) {
            return false;
        }
        try {
            return Boolean.TRUE.equals(JCRTemplate.getInstance().doExecuteWithSystemSession(session -> {
                JCRUserNode user = userManagerService.lookupUser(userId, session);
                if (user == null || !user.isNodeType(MIXIN_LOCKOUT)) {
                    return false;
                }
                long failures = user.hasProperty(PROP_FAILED_ATTEMPTS)
                        ? user.getProperty(PROP_FAILED_ATTEMPTS).getLong() : 0L;
                long windowStart = user.hasProperty(PROP_WINDOW_START)
                        ? user.getProperty(PROP_WINDOW_START).getLong() : 0L;
                return lockedNow(failures, windowStart, System.currentTimeMillis());
            }));
        } catch (RepositoryException e) {
            logger.warn("Failed to read TOTP lockout state for user {}: {}", userId, e.getMessage());
            return false; // fail open
        }
    }

    /**
     * Record a failed code attempt. Returns true if the user is now locked out.
     */
    public boolean recordFailure(String userId) {
        if (userId == null) {
            return false;
        }
        try {
            return Boolean.TRUE.equals(JCRTemplate.getInstance().doExecuteWithSystemSession(session -> {
                JCRUserNode user = userManagerService.lookupUser(userId, session);
                if (user == null) {
                    return false;
                }
                if (!user.isNodeType(MIXIN_LOCKOUT)) {
                    user.addMixin(MIXIN_LOCKOUT);
                }
                long now = System.currentTimeMillis();
                long failures = user.hasProperty(PROP_FAILED_ATTEMPTS)
                        ? user.getProperty(PROP_FAILED_ATTEMPTS).getLong() : 0L;
                long windowStart = user.hasProperty(PROP_WINDOW_START)
                        ? user.getProperty(PROP_WINDOW_START).getLong() : 0L;
                long[] next = afterFailure(failures, windowStart, now);
                user.setProperty(PROP_FAILED_ATTEMPTS, next[0]);
                user.setProperty(PROP_WINDOW_START, next[1]);
                session.save();
                if (next[0] >= MAX_FAILURES) {
                    logger.warn("TOTP management lockout triggered for user {} ({} failures in window)",
                            userId, next[0]);
                    return true;
                }
                return false;
            }));
        } catch (RepositoryException e) {
            logger.warn("Failed to record TOTP lockout failure for user {}: {}", userId, e.getMessage());
            return false; // fail open
        }
    }

    /**
     * Clear the failure counter on success.
     */
    public void recordSuccess(String userId) {
        if (userId == null) {
            return;
        }
        try {
            JCRTemplate.getInstance().doExecuteWithSystemSession(session -> {
                JCRUserNode user = userManagerService.lookupUser(userId, session);
                if (user == null || !user.isNodeType(MIXIN_LOCKOUT)) {
                    return null;
                }
                user.setProperty(PROP_FAILED_ATTEMPTS, 0L);
                user.setProperty(PROP_WINDOW_START, 0L);
                session.save();
                return null;
            });
        } catch (RepositoryException e) {
            logger.warn("Failed to clear TOTP lockout state for user {}: {}", userId, e.getMessage());
        }
    }
}
