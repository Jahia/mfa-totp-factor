package org.jahia.modules.upa.mfa.extensions.internal;

import org.jahia.params.valves.AuthValveContext;
import org.jahia.pipelines.PipelineException;
import org.jahia.pipelines.valves.ValveContext;
import org.junit.Test;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * The auth valve is the decisive block for a password-only {@code /cms/login} POST (the servlet
 * filter runs too late for POST). With a stubbed {@link MfaLoginGateDecision} it must:
 * <ul>
 *   <li>let a non-login request (missing username/password) continue the pipeline;</li>
 *   <li>continue the pipeline for a whitelisted client (the emergency door);</li>
 *   <li>continue the pipeline when not gated;</li>
 *   <li>BLOCK a gated, non-whitelisted password login - NOT continue the pipeline, and write a
 *       redirect to the configured login page (or {@code 403} when none is distinct);</li>
 *   <li>continue the pipeline (defense to the servlet filter) when the decision service is absent.</li>
 * </ul>
 */
public class MfaLoginGateAuthValveTest {

    @Test
    public void nonLoginRequest_continuesPipelineAndWritesNothing() throws Exception {
        StubDecision decision = new StubDecision();
        decision.gated = true; // even if it would be gated, no credentials => nothing to block
        Recorder recorder = new Recorder();
        valve(decision).invoke(authContext(requestWith(null, null), recorder.response), recorder.context());
        assertTrue("a request with no credentials must continue", recorder.invokedNext.get());
        assertNull(recorder.redirectedTo.get());
        assertNull(recorder.errorSent.get());
    }

    @Test
    public void gatedNonWhitelistedPasswordLogin_blocksWithRedirect() throws Exception {
        StubDecision decision = new StubDecision();
        decision.gated = true;
        decision.whitelisted = false;
        decision.distinctLoginUrl = "/sites/mySite/login.html";
        Recorder recorder = new Recorder();
        valve(decision).invoke(authContext(loginPost(), recorder.response), recorder.context());
        assertFalse("a gated password login must NOT continue the pipeline", recorder.invokedNext.get());
        assertEquals("/sites/mySite/login.html", recorder.redirectedTo.get());
        assertNull(recorder.errorSent.get());
    }

    @Test
    public void gatedNonWhitelistedPasswordLogin_blocksWith403WhenNoDistinctUrl() throws Exception {
        StubDecision decision = new StubDecision();
        decision.gated = true;
        decision.whitelisted = false;
        decision.distinctLoginUrl = null; // nowhere distinct to send them
        Recorder recorder = new Recorder();
        valve(decision).invoke(authContext(loginPost(), recorder.response), recorder.context());
        assertFalse(recorder.invokedNext.get());
        assertEquals(Integer.valueOf(HttpServletResponse.SC_FORBIDDEN), recorder.errorSent.get());
        assertNull(recorder.redirectedTo.get());
    }

    @Test
    public void whitelistedClient_continuesPipeline() throws Exception {
        StubDecision decision = new StubDecision();
        decision.gated = true;
        decision.whitelisted = true; // emergency door
        Recorder recorder = new Recorder();
        valve(decision).invoke(authContext(loginPost(), recorder.response), recorder.context());
        assertTrue("a whitelisted client must continue", recorder.invokedNext.get());
        assertNull(recorder.redirectedTo.get());
        assertNull(recorder.errorSent.get());
    }

    @Test
    public void notGatedPasswordLogin_continuesPipeline() throws Exception {
        StubDecision decision = new StubDecision();
        decision.gated = false;
        Recorder recorder = new Recorder();
        valve(decision).invoke(authContext(loginPost(), recorder.response), recorder.context());
        assertTrue("not gated => the login may proceed", recorder.invokedNext.get());
        assertNull(recorder.redirectedTo.get());
        assertNull(recorder.errorSent.get());
    }

    @Test
    public void blockIsIndependentOfHardGateSwitch() throws Exception {
        // The valve must block a gated login even when the hard-gate switch is OFF: the POST bypass
        // must always be closed when a site enforces MFA, regardless of loginGate.enabled.
        StubDecision decision = new StubDecision();
        decision.gated = true;
        decision.whitelisted = false;
        decision.hardGateEnabled = false;
        decision.distinctLoginUrl = "/sites/mySite/login.html";
        Recorder recorder = new Recorder();
        valve(decision).invoke(authContext(loginPost(), recorder.response), recorder.context());
        assertFalse(recorder.invokedNext.get());
        assertEquals("/sites/mySite/login.html", recorder.redirectedTo.get());
    }

    @Test
    public void decisionServiceAbsent_continuesPipeline() throws Exception {
        // The decision service is not available (bundle starting/stopping): the valve cannot decide,
        // so it lets the pipeline proceed (the servlet filter still applies as defense-in-depth).
        Recorder recorder = new Recorder();
        valve(null).invoke(authContext(loginPost(), recorder.response), recorder.context());
        assertTrue(recorder.invokedNext.get());
        assertNull(recorder.redirectedTo.get());
        assertNull(recorder.errorSent.get());
    }

    @Test
    public void nonAuthValveContext_continuesPipeline() throws Exception {
        Recorder recorder = new Recorder();
        valve(new StubDecision()).invoke("not an AuthValveContext", recorder.context());
        assertTrue(recorder.invokedNext.get());
    }

    @Test
    public void initializeSetsTheId() {
        MfaLoginGateAuthValve valve = new MfaLoginGateAuthValve();
        valve.initialize();
        assertEquals(MfaLoginGateAuthValve.VALVE_ID, valve.getId());
    }

    // --- Helpers --------------------------------------------------------------------------------

    /** A valve whose OSGi lookup is short-circuited to return the given (possibly null) stub. */
    private static MfaLoginGateAuthValve valve(MfaLoginGateDecision decision) {
        return new MfaLoginGateAuthValve() {
            @Override
            protected MfaLoginGateDecision lookupDecision() {
                return decision;
            }
        };
    }

    private static AuthValveContext authContext(HttpServletRequest request, HttpServletResponse response) {
        return new AuthValveContext(request, response, null);
    }

    /** A POST /cms/login carrying both username and password (a password-login attempt). */
    private static HttpServletRequest loginPost() {
        return requestWith("alice", "s3cret");
    }

    private static HttpServletRequest requestWith(String username, String password) {
        return (HttpServletRequest) Proxy.newProxyInstance(
                MfaLoginGateAuthValveTest.class.getClassLoader(),
                new Class<?>[]{HttpServletRequest.class},
                (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "getParameter":
                            if ("username".equals(args[0])) {
                                return username;
                            }
                            if ("password".equals(args[0])) {
                                return password;
                            }
                            return null;
                        case "getContextPath":
                            return "";
                        case "getRequestURI":
                            return "/cms/login";
                        default:
                            return null;
                    }
                });
    }

    /** A stub decision with directly settable answers for the valve's three queries. */
    private static final class StubDecision extends MfaLoginGateDecision {
        private boolean gated;
        private boolean whitelisted;
        private boolean hardGateEnabled;
        private String distinctLoginUrl;

        @Override
        public boolean isGated(HttpServletRequest request) {
            return gated;
        }

        @Override
        public boolean isClientWhitelisted(HttpServletRequest request) {
            return whitelisted;
        }

        @Override
        public boolean isHardGateEnabled() {
            return hardGateEnabled;
        }

        @Override
        public String resolveDistinctLoginUrl(HttpServletRequest request) {
            return distinctLoginUrl;
        }
    }

    /** Records whether the pipeline was continued (invokeNext) and any response written. */
    private static final class Recorder {
        private final AtomicBoolean invokedNext = new AtomicBoolean(false);
        private final AtomicReference<String> redirectedTo = new AtomicReference<>();
        private final AtomicReference<Integer> errorSent = new AtomicReference<>();

        private final HttpServletResponse response = (HttpServletResponse) Proxy.newProxyInstance(
                Recorder.class.getClassLoader(),
                new Class<?>[]{HttpServletResponse.class},
                (proxy, method, args) -> {
                    if ("sendRedirect".equals(method.getName())) {
                        redirectedTo.set((String) args[0]);
                    } else if ("sendError".equals(method.getName())) {
                        errorSent.set((Integer) args[0]);
                    }
                    return null;
                });

        private ValveContext context() {
            return new ValveContext() {
                @Override
                public void invokeNext(Object context) throws PipelineException {
                    invokedNext.set(true);
                }

                @Override
                public Map<String, Object> getEnvironment() {
                    return new HashMap<>();
                }
            };
        }
    }
}
