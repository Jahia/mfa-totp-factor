package org.jahia.modules.upa.mfa.totp;

import org.jahia.modules.upa.mfa.MfaException;
import org.jahia.modules.upa.mfa.MfaSessionContext;
import org.jahia.modules.upa.mfa.VerificationContext;
import org.junit.Before;
import org.junit.Test;

import javax.jcr.RepositoryException;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Unit-level coverage for the login-time chokepoint: {@link TotpFactorProvider#verify}
 * MUST persist {@code lastUsedCounter} atomically and reject any subsequent verification
 * that re-submits the same code. This guards against the regression that allowed a
 * replayed TOTP at login to succeed because the provider verified without consuming.
 */
public class TotpFactorProviderTest {

    private static final String USER_ID = "alice";

    private TotpService totpService;
    private FakeUserStore userStore;
    private TotpFactorProvider provider;
    private String secretBase32;

    @Before
    public void setUp() {
        totpService = new TotpService();
        secretBase32 = totpService.toBase32(totpService.generateSecret());
        userStore = new FakeUserStore(totpService, secretBase32);
        provider = new TotpFactorProvider();
        provider.setTotpService(totpService);
        provider.setUserStore(userStore);
        provider.setBackupCodes(new BackupCodes());
        // No-op audit log: verify() records an event, but auditing must never affect the
        // verification outcome and the real (JCR-backed) log is not available in a unit test.
        provider.setAuditLog(new TotpAuditLog() {
            @Override
            public void record(String eventType, String outcome, String userId, String siteKey, String detail) {
                // no-op
            }
        });
    }

    @Test
    public void verify_freshCode_succeedsAndConsumesCounter() throws Exception {
        long now = System.currentTimeMillis() / 1000L;
        long counter = now / TotpService.TIME_STEP_SECONDS;
        String code = totpService.generateCode(totpService.fromBase32(secretBase32), counter);

        assertTrue("first use of a fresh code must succeed", provider.verify(ctx(code)));
        assertTrue("lastUsedCounter must have been bumped to the matched counter",
                userStore.lastUsedCounter >= counter);
    }

    @Test
    public void verify_replayedCode_isRejected() throws Exception {
        long now = System.currentTimeMillis() / 1000L;
        long counter = now / TotpService.TIME_STEP_SECONDS;
        String code = totpService.generateCode(totpService.fromBase32(secretBase32), counter);

        // First use → success
        assertTrue(provider.verify(ctx(code)));
        // Second use of the SAME code → must be rejected (replay protection)
        assertFalse("replayed TOTP code MUST be rejected at login", provider.verify(ctx(code)));
    }

    private static VerificationContext ctx(String code) {
        MfaSessionContext sessionContext = new MfaSessionContext(
                USER_ID, Locale.ENGLISH, null, false, Collections.singletonList("totp"));
        return new VerificationContext(sessionContext, null, code, null, null);
    }

    /**
     * In-memory stand-in for {@link TotpUserStore}. Overrides every method that touches JCR.
     * {@link #verifyAndConsumeTotp} replicates the production chokepoint's atomicity:
     * read-modify-write of {@code lastUsedCounter} under a single guard.
     */
    private static class FakeUserStore extends TotpUserStore {
        private final TotpService totpService;
        private final String secret;
        long lastUsedCounter = 0L;
        final List<String> backupHashes = Collections.emptyList();

        FakeUserStore(TotpService totpService, String secret) {
            this.totpService = totpService;
            this.secret = secret;
        }

        @Override
        public boolean isEnrolled(String userId) {
            return true;
        }

        @Override
        public TotpUserSettings load(String userId) {
            return new TotpUserSettings(true, secret, lastUsedCounter, backupHashes);
        }

        @Override
        public synchronized Optional<Long> verifyAndConsumeTotp(String userId, TotpService svc,
                                                                 String submittedCode, long nowSeconds,
                                                                 int driftWindows) {
            byte[] key = svc.fromBase32(secret);
            Optional<Long> matched = svc.verifyCode(key, submittedCode, nowSeconds,
                    lastUsedCounter, driftWindows);
            if (matched.isPresent()) {
                lastUsedCounter = matched.get();
            }
            return matched;
        }

        @Override
        public void updateLastUsedCounter(String userId, long counter) {
            this.lastUsedCounter = counter;
        }

        @Override
        public void consumeBackupCode(String userId, int index) throws RepositoryException {
            // no-op; backup-code path not exercised here
        }
    }

    // unused param suppression for static analysis
    @SuppressWarnings("unused")
    private static void touch(MfaException e) { /* keep import */ }
}
