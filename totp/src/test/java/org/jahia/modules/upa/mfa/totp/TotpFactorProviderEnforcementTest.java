package org.jahia.modules.upa.mfa.totp;

import org.jahia.modules.upa.mfa.MfaException;
import org.jahia.modules.upa.mfa.MfaFactorState;
import org.jahia.modules.upa.mfa.MfaService;
import org.jahia.modules.upa.mfa.MfaSession;
import org.jahia.modules.upa.mfa.MfaSessionContext;
import org.jahia.modules.upa.mfa.PreparationContext;
import org.jahia.modules.upa.mfa.extensions.MfaGlobalPolicy;
import org.jahia.modules.upa.mfa.extensions.MfaSiteProvider;
import org.jahia.modules.upa.mfa.extensions.SkippablePreparation;
import org.junit.Before;
import org.junit.Test;

import javax.servlet.http.HttpServletRequest;
import java.io.Serializable;
import java.lang.reflect.Proxy;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * The global pick-one enforcement decision table in {@link TotpFactorProvider#prepare}:
 * enforcement is platform-wide ({@link MfaGlobalPolicy}); a user must satisfy it with at least
 * ONE of the enforced factors, the others skip. Covers the site-scoped rows — site disabled,
 * non-enforced opt-in, pick-one satisfied in-session, sibling factor configured, and the
 * grace-window/enrollment-required terminal cases.
 */
public class TotpFactorProviderEnforcementTest {

    private static final String USER_ID = "alice";
    private static final String SITE = "siteA";

    private TotpFactorProvider provider;
    private FakeUserStore userStore;
    private FakeSiteSettingsStore siteSettingsStore;
    private MfaGlobalPolicy policy;
    private MfaSession session;

    @Before
    public void setUp() {
        provider = new TotpFactorProvider();
        userStore = new FakeUserStore();
        siteSettingsStore = new FakeSiteSettingsStore();
        policy = new MfaGlobalPolicy();
        session = new MfaSession(new MfaSessionContext(
                USER_ID, Locale.ENGLISH, SITE, false, Arrays.asList("totp", "webauthn")));

        provider.setTotpService(new TotpService());
        provider.setUserStore(userStore);
        provider.setSiteSettingsStore(siteSettingsStore);
        provider.setAuditLog(new TotpAuditLog() {
            @Override
            public void recordEvent(String eventType, String outcome, String userId, String siteKey, String detail) {
                // no-op
            }
        });
        provider.setGlobalPolicy(policy);
        provider.setMfaService((MfaService) Proxy.newProxyInstance(
                getClass().getClassLoader(), new Class<?>[]{MfaService.class},
                (proxy, method, args) -> "getMfaSession".equals(method.getName()) ? session : null));
        // DS invokes @Activate after the @Reference setters; mirror that so the shared
        // enforcementDecider is built. siteProviders is held by reference, so bindSiteProvider
        // calls made later inside individual tests remain visible to the decider.
        provider.activate();
    }

    private void configurePolicy(String enforcedFactors, String graceDays) {
        Map<String, Object> props = new HashMap<>();
        props.put("enforcedFactors", enforcedFactors);
        if (graceDays != null) {
            props.put("graceDays", graceDays);
        }
        policy.activate(props);
    }

    private PreparationContext ctx() {
        HttpServletRequest request = (HttpServletRequest) Proxy.newProxyInstance(
                getClass().getClassLoader(), new Class<?>[]{HttpServletRequest.class},
                (proxy, method, args) -> null);
        return new PreparationContext(session.getContext(), request, null);
    }

    private static boolean isSkipped(Serializable prep) {
        return prep instanceof TotpPreparationResult && ((TotpPreparationResult) prep).isSkipped();
    }

    // --- site activation rows -------------------------------------------------------------

    @Test
    public void siteDisabled_skips() throws Exception {
        siteSettingsStore.enabled = false;
        configurePolicy("totp", null);
        assertTrue(isSkipped(provider.prepare(ctx())));
    }

    // --- non-enforced rows ----------------------------------------------------------------

    @Test
    public void notEnforced_enrolledUser_isChallenged() throws Exception {
        configurePolicy("", null);
        userStore.enrolled = true;
        assertFalse("an enrolled user must be challenged even without enforcement",
                isSkipped(provider.prepare(ctx())));
    }

    @Test
    public void notEnforced_unenrolledUser_skips() throws Exception {
        configurePolicy("", null);
        userStore.enrolled = false;
        assertTrue(isSkipped(provider.prepare(ctx())));
    }

    // --- enforced rows ---------------------------------------------------------------------

    @Test
    public void enforced_anotherEnforcedFactorAlreadyVerified_skips() throws Exception {
        configurePolicy("totp,webauthn", null);
        userStore.enrolled = true; // even an enrolled user skips once pick-one is satisfied
        session.getOrCreateFactorState("webauthn").setVerified(true);
        assertTrue(isSkipped(provider.prepare(ctx())));
    }

    @Test
    public void enforced_enrolledUser_isChallenged() throws Exception {
        configurePolicy("totp,webauthn", null);
        userStore.enrolled = true;
        assertFalse(isSkipped(provider.prepare(ctx())));
    }

    @Test
    public void enforced_siblingFactorConfigured_skips() throws Exception {
        configurePolicy("totp,webauthn", null);
        userStore.enrolled = false;
        provider.bindSiteProvider(siblingProvider("webauthn", true, true));
        assertTrue("the user will verify with the configured sibling factor",
                isSkipped(provider.prepare(ctx())));
    }

    @Test
    public void enforced_siblingConfiguredButNotRequired_stillSkips() throws Exception {
        // UPA's mfaEnabledFactors only lists totp: the configured sibling can never be
        // challenged in this session, so the sign-in completes without a second factor.
        // The skip stands (blocking would dead-end the user — pre-auth enrollment is closed
        // once any enforced factor is owned); the provider logs a loud misconfiguration
        // warning instead.
        configurePolicy("totp,webauthn", null);
        userStore.enrolled = false;
        session = new MfaSession(new MfaSessionContext(
                USER_ID, Locale.ENGLISH, SITE, false, Collections.singletonList("totp")));
        provider.bindSiteProvider(siblingProvider("webauthn", true, true));
        assertTrue(isSkipped(provider.prepare(ctx())));
    }

    @Test
    public void enforced_siblingVerifiedBySkipDrain_doesNotSatisfyPickOne() {
        // The webauthn factor was drained as SKIPPED earlier in this session (its own pick-one
        // row deferred to a configured sibling): its verified flag is not a real verification
        // and must not satisfy pick-one here — otherwise two unchallenged factors excuse each
        // other circularly and the session completes without any challenge.
        configurePolicy("totp,webauthn", "0");
        userStore.enrolled = false;
        MfaFactorState webauthnState = session.getOrCreateFactorState("webauthn");
        webauthnState.setPreparationResult(new SkippedSiblingPreparation());
        webauthnState.setVerified(true);
        try {
            provider.prepare(ctx());
            fail("expected enrollment_required — a skip-drained sibling is not a real verification");
        } catch (MfaException e) {
            assertEquals(TotpFactorProvider.ERROR_ENROLLMENT_REQUIRED, e.getCode());
        }
    }

    @Test
    public void enforced_nothingConfigured_withinGrace_skips() throws Exception {
        configurePolicy("totp", "7");
        userStore.enrolled = false;
        userStore.graceStart = System.currentTimeMillis(); // window just started
        assertTrue(isSkipped(provider.prepare(ctx())));
    }

    @Test
    public void enforced_nothingConfigured_noGrace_throwsEnrollmentRequiredWithOffer() {
        configurePolicy("totp,webauthn", "0");
        userStore.enrolled = false;
        provider.bindSiteProvider(siblingProvider("webauthn", false, true)); // enabled on site, not configured
        try {
            provider.prepare(ctx());
            fail("expected enrollment_required");
        } catch (MfaException e) {
            assertEquals(TotpFactorProvider.ERROR_ENROLLMENT_REQUIRED, e.getCode());
            assertEquals("totp is not offered (no provider bound for it); webauthn is enabled on the site",
                    "webauthn", e.getArguments().get("enrollableFactors"));
        }
    }

    // --- no-site-context rows (vanity URLs hide the /sites/<key> prefix) -------------------

    @Test
    public void noSite_enforced_nothingConfigured_throwsEnrollmentRequiredWithOffer() {
        configurePolicy("totp", "0");
        userStore.enrolled = false;
        session = new MfaSession(new MfaSessionContext(
                USER_ID, Locale.ENGLISH, null, false, Arrays.asList("totp")));
        provider.bindSiteProvider(siblingProvider("totp", false, true));
        try {
            provider.prepare(ctx());
            fail("expected enrollment_required");
        } catch (MfaException e) {
            assertEquals(TotpFactorProvider.ERROR_ENROLLMENT_REQUIRED, e.getCode());
            assertEquals("without a site, installed enforced factors are offered",
                    "totp", e.getArguments().get("enrollableFactors"));
        }
    }

    @Test
    public void noSite_notEnforced_unenrolled_throwsNotEnrolled() {
        configurePolicy("", null);
        userStore.enrolled = false;
        session = new MfaSession(new MfaSessionContext(
                USER_ID, Locale.ENGLISH, null, false, Arrays.asList("totp")));
        try {
            provider.prepare(ctx());
            fail("expected not_enrolled (legacy no-site behavior without enforcement)");
        } catch (MfaException e) {
            assertEquals(TotpFactorProvider.ERROR_NOT_ENROLLED, e.getCode());
        }
    }

    @Test
    public void enforced_nothingConfigured_graceExpired_throwsEnrollmentRequired() {
        configurePolicy("totp", "1");
        userStore.enrolled = false;
        userStore.graceStart = System.currentTimeMillis() - 2L * 24 * 60 * 60 * 1000; // 2 days ago
        try {
            provider.prepare(ctx());
            fail("expected enrollment_required");
        } catch (MfaException e) {
            assertEquals(TotpFactorProvider.ERROR_ENROLLMENT_REQUIRED, e.getCode());
        }
    }

    // --- fakes ------------------------------------------------------------------------------

    /** Stands in for the sibling module's preparation result marked as a pick-one skip. */
    private static class SkippedSiblingPreparation implements SkippablePreparation, Serializable {
        @Override
        public boolean isSkipped() {
            return true;
        }
    }

    private static MfaSiteProvider siblingProvider(String type, boolean configuredForUser, boolean enabledForSite) {
        return new MfaSiteProvider() {
            @Override
            public String getFactorType() {
                return type;
            }

            @Override
            public boolean isEnabledForSite(String siteKey) {
                return enabledForSite;
            }

            @Override
            public boolean isAnySiteEnabled() {
                return enabledForSite;
            }

            @Override
            public boolean isConfiguredForUser(String userId) {
                return configuredForUser;
            }
        };
    }

    private static class FakeUserStore extends TotpUserStore {
        boolean enrolled;
        long graceStart = System.currentTimeMillis();

        @Override
        public boolean isEnrolled(String userId) {
            return enrolled;
        }

        @Override
        public boolean isMemberOfAnyGroup(String userId, java.util.Collection<String> groupNames) {
            return true; // empty policy groups = everyone in scope
        }

        @Override
        public long getOrStartGraceMillis(String userId, long nowMillis) {
            return graceStart;
        }
    }

    private static class FakeSiteSettingsStore extends TotpSiteSettingsStore {
        boolean enabled = true;

        @Override
        public TotpSiteSettings load(String siteKey) {
            return new TotpSiteSettings(enabled, Collections.emptyList(), null, null);
        }
    }
}
