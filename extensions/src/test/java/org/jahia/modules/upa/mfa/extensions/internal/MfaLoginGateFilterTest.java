package org.jahia.modules.upa.mfa.extensions.internal;

import org.junit.Test;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletResponse;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.jahia.modules.upa.mfa.extensions.internal.MfaLoginGateDecisionTest.decisionWith;
import static org.jahia.modules.upa.mfa.extensions.internal.MfaLoginGateDecisionTest.loginRequest;
import static org.jahia.modules.upa.mfa.extensions.internal.MfaLoginGateDecisionTest.provider;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

/**
 * The servlet filter's mapping from the shared {@link MfaLoginGateDecision} onto servlet outcomes
 * (chain / redirect / 403). The decision logic itself (whitelist, gating, URL resolution) is tested
 * in {@link MfaLoginGateDecisionTest}; here we wire a decision into the filter and assert the
 * terminal action {@code doFilter} takes. The filter is defense-in-depth (mainly the GET case);
 * the decisive POST block lives in {@link MfaLoginGateAuthValveTest}.
 */
public class MfaLoginGateFilterTest {

    // --- Automatic mode: /cms/login reachable ONLY when explicitly configured as loginUrl ----

    @Test
    public void automaticMode_customLoginPage_redirectsThere() throws Exception {
        MfaLoginGateFilter gate = filterWith(decisionWith("totp", "/sites/mySite/login.html",
                provider("totp", true, true, false)));
        Recorder recorder = new Recorder();
        gate.doFilter(loginRequest(), recorder.response(), recorder.chain());
        assertEquals("/sites/mySite/login.html", recorder.redirectedTo.get());
        assertNull("the chain must not proceed to the password-only valve", recorder.chained.get());
    }

    @Test
    public void automaticMode_cmsLoginConfigured_allowsThrough() throws Exception {
        // The operator deliberately chose the default screen: respect it.
        MfaLoginGateFilter gate = filterWith(decisionWith("totp", "/cms/login",
                provider("totp", true, true, false)));
        Recorder recorder = new Recorder();
        gate.doFilter(loginRequest(), recorder.response(), recorder.chain());
        assertNotNull(recorder.chained.get());
        assertNull(recorder.errorSent.get());
        assertNull(recorder.redirectedTo.get());
    }

    @Test
    public void automaticMode_noLoginUrlConfigured_blocksWith403() throws Exception {
        // Enforcement with the default password-only screen reachable = silent MFA bypass.
        MfaLoginGateFilter gate = filterWith(decisionWith("totp", (String) null,
                provider("totp", true, true, false)));
        Recorder recorder = new Recorder();
        gate.doFilter(loginRequest(), recorder.response(), recorder.chain());
        assertEquals(Integer.valueOf(HttpServletResponse.SC_FORBIDDEN), recorder.errorSent.get());
        assertNull(recorder.chained.get());
    }

    @Test
    public void automaticMode_standsDownWithoutEnforcement() throws Exception {
        MfaLoginGateFilter gate = filterWith(decisionWith("", "/sites/mySite/login.html",
                provider("totp", true, true, false)));
        Recorder recorder = new Recorder();
        gate.doFilter(loginRequest(), recorder.response(), recorder.chain());
        assertNotNull("no enforcement → the endpoint is no bypass", recorder.chained.get());
        assertNull(recorder.redirectedTo.get());
    }

    // --- Explicit hard gate -------------------------------------------------------------------

    @Test
    public void explicitHardGate_redirectsToConfiguredLoginPage() throws Exception {
        // The hard gate reroutes a non-whitelisted client to the configured MFA login page instead
        // of a bare 403 (it still never chains through to the password-only screen).
        MfaLoginGateFilter gate = filterWith(hardGate("/sites/mySite/login.html"));
        Recorder recorder = new Recorder();
        gate.doFilter(loginRequest(), recorder.response(), recorder.chain());
        assertEquals("/sites/mySite/login.html", recorder.redirectedTo.get());
        assertNull("a redirect, not a 403", recorder.errorSent.get());
        assertNull("must not reach the password-only valve", recorder.chained.get());
    }

    @Test
    public void explicitHardGate_forbidsWhenNoDistinctLoginUrl() throws Exception {
        // No login URL configured -> nowhere distinct to send them -> 403.
        Recorder noUrl = new Recorder();
        filterWith(hardGate(null)).doFilter(loginRequest(), noUrl.response(), noUrl.chain());
        assertEquals(Integer.valueOf(HttpServletResponse.SC_FORBIDDEN), noUrl.errorSent.get());
        assertNull(noUrl.redirectedTo.get());

        // Login URL IS /cms/login itself -> redirecting there would loop -> 403 (never pass through).
        Recorder cmsLogin = new Recorder();
        filterWith(hardGate("/cms/login")).doFilter(loginRequest(), cmsLogin.response(), cmsLogin.chain());
        assertEquals(Integer.valueOf(HttpServletResponse.SC_FORBIDDEN), cmsLogin.errorSent.get());
        assertNull("the hard gate never chains through to the password-only screen", cmsLogin.chained.get());
    }

    @Test
    public void notGated_chainsThrough() throws Exception {
        MfaLoginGateFilter gate = filterWith(decisionWith("", provider("totp", false, false, false)));
        Recorder recorder = new Recorder();
        gate.doFilter(loginRequest(), recorder.response(), recorder.chain());
        assertNotNull(recorder.chained.get());
        assertNull(recorder.errorSent.get());
        assertNull(recorder.redirectedTo.get());
    }

    private static MfaLoginGateDecision hardGate(String globalLoginUrl) {
        MfaLoginGateDecision decision = decisionWith("totp", globalLoginUrl, provider("totp", true, true, false));
        Map<String, Object> props = new HashMap<>();
        props.put("enforcedFactors", "totp");
        props.put(MfaLoginGateDecision.CONFIG_GATE_ENABLED, "true");
        decision.activate(props);
        return decision;
    }

    private static MfaLoginGateFilter filterWith(MfaLoginGateDecision decision) {
        MfaLoginGateFilter filter = new MfaLoginGateFilter();
        filter.setDecision(decision);
        return filter;
    }

    /** Records which terminal action doFilter took: chain, sendRedirect or sendError. */
    private static final class Recorder {
        private final AtomicReference<Boolean> chained = new AtomicReference<>();
        private final AtomicReference<String> redirectedTo = new AtomicReference<>();
        private final AtomicReference<Integer> errorSent = new AtomicReference<>();

        private HttpServletResponse response() {
            return (HttpServletResponse) Proxy.newProxyInstance(
                    MfaLoginGateFilterTest.class.getClassLoader(),
                    new Class<?>[]{HttpServletResponse.class},
                    (proxy, method, args) -> {
                        if ("sendRedirect".equals(method.getName())) {
                            redirectedTo.set((String) args[0]);
                        } else if ("sendError".equals(method.getName())) {
                            errorSent.set((Integer) args[0]);
                        }
                        return null;
                    });
        }

        private FilterChain chain() {
            return (request, response) -> chained.set(Boolean.TRUE);
        }
    }
}
