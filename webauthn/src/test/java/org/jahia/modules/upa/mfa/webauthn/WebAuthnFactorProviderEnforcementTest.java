package org.jahia.modules.upa.mfa.webauthn;

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
 * The global pick-one enforcement decision table in {@link WebAuthnFactorProvider#prepare}
 * (mirrors the TOTP test for the rows that do not require a live assertion ceremony).
 */
public class WebAuthnFactorProviderEnforcementTest {

    private static final String USER_ID = "alice";
    private static final String SITE = "siteA";

    private WebAuthnFactorProvider provider;
    private FakeCredentialStore credentialStore;
    private FakeSiteSettingsStore siteSettingsStore;
    private MfaGlobalPolicy policy;
    private MfaSession session;

    @Before
    public void setUp() {
        provider = new WebAuthnFactorProvider();
        credentialStore = new FakeCredentialStore();
        siteSettingsStore = new FakeSiteSettingsStore();
        policy = new MfaGlobalPolicy();
        session = new MfaSession(new MfaSessionContext(
                USER_ID, Locale.ENGLISH, SITE, false, Arrays.asList("totp", "webauthn")));

        provider.setCredentialStore(credentialStore);
        provider.setSiteSettingsStore(siteSettingsStore);
        provider.setAuditLog(new WebAuthnAuditLog() {
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
        return prep instanceof WebAuthnPreparationResult && ((WebAuthnPreparationResult) prep).isSkipped();
    }

    @Test
    public void siteDisabled_skips() throws Exception {
        siteSettingsStore.enabled = false;
        configurePolicy("webauthn", null);
        assertTrue(isSkipped(provider.prepare(ctx())));
    }

    @Test
    public void notEnforced_unregisteredUser_skips() throws Exception {
        configurePolicy("", null);
        credentialStore.registered = false;
        assertTrue(isSkipped(provider.prepare(ctx())));
    }

    @Test
    public void enforced_anotherEnforcedFactorAlreadyVerified_skips() throws Exception {
        configurePolicy("totp,webauthn", null);
        credentialStore.registered = true;
        session.getOrCreateFactorState("totp").setVerified(true);
        assertTrue(isSkipped(provider.prepare(ctx())));
    }

    @Test
    public void enforced_siblingFactorConfigured_skips() throws Exception {
        configurePolicy("totp,webauthn", null);
        credentialStore.registered = false;
        provider.bindSiteProvider(siblingProvider("totp", true, true));
        assertTrue(isSkipped(provider.prepare(ctx())));
    }

    @Test
    public void enforced_siblingConfiguredButNotRequired_stillSkips() throws Exception {
        // Mirrors the TOTP row: the configured sibling is not in UPA's mfaEnabledFactors, so
        // it can never be challenged in this session — skip stands, a misconfiguration
        // warning is logged.
        configurePolicy("totp,webauthn", null);
        credentialStore.registered = false;
        session = new MfaSession(new MfaSessionContext(
                USER_ID, Locale.ENGLISH, SITE, false, Collections.singletonList("webauthn")));
        provider.bindSiteProvider(siblingProvider("totp", true, true));
        assertTrue(isSkipped(provider.prepare(ctx())));
    }

    @Test
    public void enforced_siblingSkipDrained_registeredUserIsStillChallenged() throws Exception {
        // The reported circular-skip bug: the user owns a passkey but no TOTP. Picking the
        // TOTP step first drains it as SKIPPED (its pick-one row defers to the registered
        // webauthn credential) — that drain must NOT satisfy pick-one here, or the session
        // completes with no challenge at all. The registered user gets a real assertion.
        configurePolicy("totp,webauthn", null);
        credentialStore.registered = true;
        provider.setWebAuthnService(new FakeWebAuthnService());
        MfaFactorState totpState = session.getOrCreateFactorState("totp");
        totpState.setPreparationResult(new SkippedSiblingPreparation());
        totpState.setVerified(true);
        assertFalse("a registered user must get a real assertion challenge",
                isSkipped(provider.prepare(ctx())));
    }

    @Test
    public void enforced_siblingSkipDrained_nothingConfigured_throwsRegistrationRequired() {
        configurePolicy("totp,webauthn", "0");
        credentialStore.registered = false;
        MfaFactorState totpState = session.getOrCreateFactorState("totp");
        totpState.setPreparationResult(new SkippedSiblingPreparation());
        totpState.setVerified(true);
        try {
            provider.prepare(ctx());
            fail("expected registration_required — a skip-drained sibling is not a real verification");
        } catch (MfaException e) {
            assertEquals(WebAuthnFactorProvider.ERROR_REGISTRATION_REQUIRED, e.getCode());
        }
    }

    @Test
    public void enforced_nothingConfigured_withinGrace_skips() throws Exception {
        configurePolicy("webauthn", "7");
        credentialStore.registered = false;
        credentialStore.graceStart = System.currentTimeMillis();
        assertTrue(isSkipped(provider.prepare(ctx())));
    }

    @Test
    public void enforced_nothingConfigured_noGrace_throwsRegistrationRequiredWithOffer() {
        configurePolicy("totp,webauthn", "0");
        credentialStore.registered = false;
        provider.bindSiteProvider(siblingProvider("totp", false, true));
        try {
            provider.prepare(ctx());
            fail("expected registration_required");
        } catch (MfaException e) {
            assertEquals(WebAuthnFactorProvider.ERROR_REGISTRATION_REQUIRED, e.getCode());
            assertEquals("totp", e.getArguments().get("enrollableFactors"));
        }
    }

    // --- no-site-context rows (vanity URLs hide the /sites/<key> prefix) -------------------

    @Test
    public void noSite_enforced_nothingConfigured_throwsRegistrationRequiredWithOffer() {
        configurePolicy("webauthn", "0");
        credentialStore.registered = false;
        session = new MfaSession(new MfaSessionContext(
                USER_ID, Locale.ENGLISH, null, false, Arrays.asList("webauthn")));
        provider.bindSiteProvider(siblingProvider("webauthn", false, true));
        try {
            provider.prepare(ctx());
            fail("expected registration_required");
        } catch (MfaException e) {
            assertEquals(WebAuthnFactorProvider.ERROR_REGISTRATION_REQUIRED, e.getCode());
            assertEquals("webauthn", e.getArguments().get("enrollableFactors"));
        }
    }

    @Test
    public void noSite_notEnforced_unregistered_throwsNotRegistered() {
        configurePolicy("", null);
        credentialStore.registered = false;
        session = new MfaSession(new MfaSessionContext(
                USER_ID, Locale.ENGLISH, null, false, Arrays.asList("webauthn")));
        try {
            provider.prepare(ctx());
            fail("expected not_registered (legacy no-site behavior without enforcement)");
        } catch (MfaException e) {
            assertEquals(WebAuthnFactorProvider.ERROR_NOT_REGISTERED, e.getCode());
        }
    }

    @Test
    public void enforced_nothingConfigured_graceExpired_throwsRegistrationRequired() {
        configurePolicy("webauthn", "1");
        credentialStore.registered = false;
        credentialStore.graceStart = System.currentTimeMillis() - 2L * 24 * 60 * 60 * 1000;
        try {
            provider.prepare(ctx());
            fail("expected registration_required");
        } catch (MfaException e) {
            assertEquals(WebAuthnFactorProvider.ERROR_REGISTRATION_REQUIRED, e.getCode());
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

    private static class FakeWebAuthnService extends WebAuthnService {
        @Override
        public AssertionCeremony startAssertion(String username) {
            return new AssertionCeremony("{}", "{}");
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

    private static class FakeCredentialStore extends WebAuthnCredentialStore {
        boolean registered;
        long graceStart = System.currentTimeMillis();

        @Override
        public boolean hasCredentials(String userId) {
            return registered;
        }

        @Override
        public long getOrStartGraceMillis(String userId, long nowMillis) {
            return graceStart;
        }

        @Override
        public boolean isMemberOfAnyGroup(String userId, java.util.Collection<String> groupNames,
                                          org.jahia.services.usermanager.JahiaGroupManagerService groupManagerService) {
            return true; // empty policy groups = everyone in scope
        }
    }

    private static class FakeSiteSettingsStore extends WebAuthnSiteSettingsStore {
        boolean enabled = true;

        @Override
        public WebAuthnSiteSettings load(String siteKey) {
            return new WebAuthnSiteSettings(enabled, Collections.emptyList());
        }
    }
}
