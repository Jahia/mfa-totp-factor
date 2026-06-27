package org.jahia.modules.upa.mfa.extensions.internal;

import org.jahia.modules.upa.mfa.extensions.MfaGlobalPolicy;
import org.jahia.modules.upa.mfa.extensions.MfaSiteConfigService;
import org.jahia.modules.upa.mfa.extensions.MfaSiteProvider;
import org.junit.Test;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.jahia.modules.upa.mfa.extensions.internal.MfaLoginGateFilter.isCmsLogin;
import static org.jahia.modules.upa.mfa.extensions.internal.MfaLoginGateFilter.isIpLiteral;
import static org.jahia.modules.upa.mfa.extensions.internal.MfaLoginGateFilter.isWhitelisted;
import static org.jahia.modules.upa.mfa.extensions.internal.MfaLoginGateFilter.parseWhitelist;
import static org.jahia.modules.upa.mfa.extensions.internal.MfaLoginGateFilter.resolveClientIp;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * The /cms/login gate's whitelist matching: the client IP (first X-Forwarded-For entry) must
 * match a configured address or CIDR block. The matcher must never DNS-resolve the
 * attacker-controlled header value, and mixed IPv4/IPv6 comparisons must never match.
 */
public class MfaLoginGateFilterTest {

    // --- Whitelist parsing -------------------------------------------------------------

    @Test
    public void parsesCommaSeparatedEntriesAndTrims() {
        List<String> entries = parseWhitelist("203.0.113.7 , 10.0.0.0/8,2001:db8::/32");
        assertEquals(Arrays.asList("203.0.113.7", "10.0.0.0/8", "2001:db8::/32"), entries);
    }

    @Test
    public void blankOrNullWhitelistIsEmpty() {
        assertTrue(parseWhitelist(null).isEmpty());
        assertTrue(parseWhitelist("").isEmpty());
        assertTrue(parseWhitelist("  ,  ,").isEmpty());
    }

    @Test
    public void invalidEntriesAreDropped() {
        // hostnames, garbage, out-of-range prefixes must be ignored (and logged), not crash
        List<String> entries = parseWhitelist("evil.example.com, 10.0.0.0/99, not-an-ip, 192.168.1.1");
        assertEquals(Collections.singletonList("192.168.1.1"), entries);
    }

    // --- Exact address matching --------------------------------------------------------

    @Test
    public void exactIpv4Match() {
        List<String> wl = parseWhitelist("203.0.113.7");
        assertTrue(isWhitelisted("203.0.113.7", wl));
        assertFalse(isWhitelisted("203.0.113.8", wl));
    }

    @Test
    public void exactIpv6MatchIsFormInsensitive() {
        List<String> wl = parseWhitelist("2001:db8::1");
        assertTrue("compressed and expanded forms are the same address",
                isWhitelisted("2001:0db8:0000:0000:0000:0000:0000:0001", wl));
        assertFalse(isWhitelisted("2001:db8::2", wl));
    }

    // --- CIDR matching ------------------------------------------------------------------

    @Test
    public void ipv4CidrBoundaries() {
        List<String> wl = parseWhitelist("10.1.2.0/24");
        assertTrue(isWhitelisted("10.1.2.0", wl));
        assertTrue(isWhitelisted("10.1.2.255", wl));
        assertFalse(isWhitelisted("10.1.3.0", wl));
        assertFalse(isWhitelisted("10.1.1.255", wl));
    }

    @Test
    public void ipv4CidrNonOctetAlignedPrefix() {
        List<String> wl = parseWhitelist("192.168.0.0/22"); // covers 192.168.0.0 - 192.168.3.255
        assertTrue(isWhitelisted("192.168.3.255", wl));
        assertFalse(isWhitelisted("192.168.4.0", wl));
    }

    @Test
    public void ipv6CidrPrefix() {
        List<String> wl = parseWhitelist("2001:db8::/32");
        assertTrue(isWhitelisted("2001:db8:ffff::1", wl));
        assertFalse(isWhitelisted("2001:db9::1", wl));
    }

    @Test
    public void mixedFamiliesNeverMatch() {
        assertFalse("a v4 client must not match a v6 block",
                isWhitelisted("10.0.0.1", parseWhitelist("2001:db8::/32")));
        assertFalse("a v6 client must not match a v4 block",
                isWhitelisted("2001:db8::1", parseWhitelist("10.0.0.0/8")));
    }

    // --- Hostility of the client value ---------------------------------------------------

    @Test
    public void hostnamesAndGarbageNeverMatchAndAreNeverResolved() {
        List<String> wl = parseWhitelist("10.0.0.0/8");
        assertFalse(isWhitelisted("evil.example.com", wl));
        assertFalse(isWhitelisted("localhost", wl));
        assertFalse(isWhitelisted("", wl));
        assertFalse(isWhitelisted(null, wl));
        assertFalse(isWhitelisted("10.0.0.1; DROP TABLE", wl));
    }

    @Test
    public void emptyWhitelistMatchesNothing() {
        assertFalse(isWhitelisted("127.0.0.1", Collections.emptyList()));
    }

    @Test
    public void ipLiteralDetection() {
        assertTrue(isIpLiteral("192.168.1.1"));
        assertTrue(isIpLiteral("::1"));
        assertTrue(isIpLiteral("::ffff:192.0.2.1")); // v4-mapped v6
        assertFalse("hex-only hostnames must not be treated as IPs", isIpLiteral("abcdef"));
        assertFalse("out-of-range octets must not fall through to DNS", isIpLiteral("192.168.1.256"));
        assertFalse(isIpLiteral("example.com"));
        assertFalse(isIpLiteral(null));
        assertFalse(isIpLiteral(""));
    }

    // --- Gating decision: global policy ∩ per-site activation ---------------------------

    @Test
    public void notGatedWhenEnforcementInactiveEvenIfSitesEnabled() {
        MfaLoginGateFilter gate = gateWith("", provider("totp", true, true, false));
        assertFalse(gate.anyEnforcesForSite("siteA"));
        assertFalse(gate.computeAnySiteEnforcing());
    }

    @Test
    public void notGatedWhenEnabledFactorIsNotEnforced() {
        MfaLoginGateFilter gate = gateWith("webauthn", provider("totp", true, true, false));
        assertFalse(gate.anyEnforcesForSite("siteA"));
        assertFalse(gate.computeAnySiteEnforcing());
    }

    @Test
    public void gatedWhenAnEnforcedFactorIsEnabledOnTheSite() {
        MfaLoginGateFilter gate = gateWith("totp,webauthn",
                provider("totp", false, false, false),
                provider("webauthn", true, true, false));
        assertTrue(gate.anyEnforcesForSite("siteA"));
        assertTrue(gate.computeAnySiteEnforcing());
    }

    @Test
    public void notGatedWhenEnforcedFactorsAreDisabledOnEverySite() {
        MfaLoginGateFilter gate = gateWith("totp", provider("totp", false, false, false));
        assertFalse(gate.anyEnforcesForSite("siteA"));
        assertFalse(gate.computeAnySiteEnforcing());
    }

    @Test
    public void throwingProviderFailsClosed() {
        MfaLoginGateFilter gate = gateWith("totp", provider("totp", true, true, true));
        assertTrue("an unanswerable provider must block (fail closed)", gate.anyEnforcesForSite("siteA"));
        assertTrue(gate.computeAnySiteEnforcing());
    }

    // --- Automatic mode: /cms/login reachable ONLY when explicitly configured as loginUrl ----

    @Test
    public void isCmsLoginRecognizesTheDefaultEndpoint() {
        assertTrue(isCmsLogin("/cms/login", ""));
        assertTrue("a query string does not change the endpoint", isCmsLogin("/cms/login?site=x", ""));
        assertTrue("context path is stripped", isCmsLogin("/ctx/cms/login", "/ctx"));
        assertFalse(isCmsLogin("/sites/mySite/login.html", ""));
        assertFalse(isCmsLogin("/cms/logout", ""));
        assertFalse(isCmsLogin(null, ""));
    }

    @Test
    public void automaticMode_customLoginPage_redirectsThere() throws Exception {
        MfaLoginGateFilter gate = gateWith("totp", "/sites/mySite/login.html",
                provider("totp", true, true, false));
        Recorder recorder = new Recorder();
        gate.doFilter(loginRequest(), recorder.response(), recorder.chain());
        assertEquals("/sites/mySite/login.html", recorder.redirectedTo.get());
        assertNull("the chain must not proceed to the password-only valve", recorder.chained.get());
    }

    @Test
    public void automaticMode_cmsLoginConfigured_allowsThrough() throws Exception {
        // The operator deliberately chose the default screen: respect it.
        MfaLoginGateFilter gate = gateWith("totp", "/cms/login", provider("totp", true, true, false));
        Recorder recorder = new Recorder();
        gate.doFilter(loginRequest(), recorder.response(), recorder.chain());
        assertNotNull(recorder.chained.get());
        assertNull(recorder.errorSent.get());
        assertNull(recorder.redirectedTo.get());
    }

    @Test
    public void automaticMode_noLoginUrlConfigured_blocksWith403() throws Exception {
        // Enforcement with the default password-only screen reachable = silent MFA bypass.
        MfaLoginGateFilter gate = gateWith("totp", (String) null, provider("totp", true, true, false));
        Recorder recorder = new Recorder();
        gate.doFilter(loginRequest(), recorder.response(), recorder.chain());
        assertEquals(Integer.valueOf(HttpServletResponse.SC_FORBIDDEN), recorder.errorSent.get());
        assertNull(recorder.chained.get());
    }

    @Test
    public void automaticMode_standsDownWithoutEnforcement() throws Exception {
        MfaLoginGateFilter gate = gateWith("", "/sites/mySite/login.html",
                provider("totp", true, true, false));
        Recorder recorder = new Recorder();
        gate.doFilter(loginRequest(), recorder.response(), recorder.chain());
        assertNotNull("no enforcement → the endpoint is no bypass", recorder.chained.get());
        assertNull(recorder.redirectedTo.get());
    }

    @Test
    public void explicitHardGate_blocksEvenWithACustomLoginPage() throws Exception {
        MfaLoginGateFilter gate = gateWith("totp", "/sites/mySite/login.html",
                provider("totp", true, true, false));
        Map<String, Object> props = new HashMap<>();
        props.put("enforcedFactors", "totp");
        props.put(MfaLoginGateFilter.CONFIG_GATE_ENABLED, "true");
        gate.activate(props);
        Recorder recorder = new Recorder();
        gate.doFilter(loginRequest(), recorder.response(), recorder.chain());
        assertEquals(Integer.valueOf(HttpServletResponse.SC_FORBIDDEN), recorder.errorSent.get());
        assertNull("the hard gate never redirects", recorder.redirectedTo.get());
    }

    // --- X-Forwarded-For trust (loginGate.trustForwardedFor) ----------------------------------

    @Test
    public void resolveClientIp_trustsForwardedForByDefault() {
        HttpServletRequest request = requestWith("203.0.113.9", "198.51.100.23");
        assertEquals("the first XFF entry wins when trusted", "203.0.113.9", resolveClientIp(request, true));
    }

    @Test
    public void resolveClientIp_ignoresForwardedForWhenNotTrusted() {
        HttpServletRequest request = requestWith("203.0.113.9", "198.51.100.23");
        assertEquals("the spoofable header is ignored - socket address is used",
                "198.51.100.23", resolveClientIp(request, false));
    }

    @Test
    public void resolveClientIp_usesSocketAddressWhenNoHeader() {
        HttpServletRequest request = requestWith(null, "198.51.100.23");
        assertEquals("198.51.100.23", resolveClientIp(request, true));
        assertEquals("198.51.100.23", resolveClientIp(request, false));
    }

    @Test
    public void trustForwardedForFalse_aSpoofedWhitelistedHeaderDoesNotGetThrough() throws Exception {
        // Whitelist the proxy IP; an attacker forges X-Forwarded-For: <whitelisted> from a
        // non-whitelisted socket. With trustForwardedFor=false the gate must NOT let them through.
        MfaLoginGateFilter gate = gateWith("totp", (String) null, provider("totp", true, true, false));
        Map<String, Object> props = new HashMap<>();
        props.put("enforcedFactors", "totp");
        props.put(MfaLoginGateFilter.CONFIG_GATE_WHITELIST, "203.0.113.9");
        props.put(MfaLoginGateFilter.CONFIG_TRUST_FORWARDED_FOR, "false");
        gate.activate(props);
        Recorder recorder = new Recorder();
        gate.doFilter(requestWith("203.0.113.9", "198.51.100.23"), recorder.response(), recorder.chain());
        assertEquals("forged XFF must be ignored → blocked",
                Integer.valueOf(HttpServletResponse.SC_FORBIDDEN), recorder.errorSent.get());
        assertNull(recorder.chained.get());
    }

    // --- Startup fail-CLOSED while the per-site config service is not ready --------------------

    @Test
    public void noSiteContext_failsClosedWhileConfigServiceNotReady() throws Exception {
        // Enforcement active, no site context, and the per-site config service has NOT finished its
        // eager scan: the no-site path must fail CLOSED (block) rather than let password-only through.
        MfaLoginGateFilter gate = gateWith("totp", (String) null, provider("totp", true, false, false));
        gate.setSiteConfigService(new MfaSiteConfigService()); // never activated → isReady()==false
        Recorder recorder = new Recorder();
        gate.doFilter(loginRequest(), recorder.response(), recorder.chain());
        assertEquals("not-ready + enforcement active must block",
                Integer.valueOf(HttpServletResponse.SC_FORBIDDEN), recorder.errorSent.get());
        assertNull("must not reach the password-only valve", recorder.chained.get());
    }

    @Test
    public void noSiteContext_standsDownWhenConfigServiceReadyWithNoSites() throws Exception {
        // The companion to the fail-CLOSED-while-not-ready case: once the per-site config service
        // HAS activated (isReady()==true) and no site enforces, the readiness guard must NOT keep
        // over-blocking. Enforcement is active but no factor is enabled on any site, so /cms/login
        // is no bypass and the gate must chain through. This proves the guard blocks ONLY during the
        // startup window, not whenever a service is wired.
        MfaLoginGateFilter gate = gateWith("totp", (String) null, provider("totp", false, false, false));
        gate.setSiteConfigService(activatedEmptyConfigService());
        Recorder recorder = new Recorder();
        gate.doFilter(loginRequest(), recorder.response(), recorder.chain());
        assertNotNull("ready + no site enforcing → the endpoint is no bypass, chain through",
                recorder.chained.get());
        assertNull(recorder.errorSent.get());
        assertNull(recorder.redirectedTo.get());
    }

    /** A {@link MfaSiteConfigService} activated against an empty etc dir: {@code isReady()==true}, no sites. */
    private static MfaSiteConfigService activatedEmptyConfigService() throws Exception {
        Path emptyEtc = Files.createTempDirectory("mfa-gate-empty-etc");
        emptyEtc.toFile().deleteOnExit();
        String previous = System.getProperty("karaf.etc");
        System.setProperty("karaf.etc", emptyEtc.toAbsolutePath().toString());
        try {
            MfaSiteConfigService service = new MfaSiteConfigService();
            service.activate(); // eager scan over an empty dir → ready, nothing loaded
            return service;
        } finally {
            if (previous == null) {
                System.clearProperty("karaf.etc");
            } else {
                System.setProperty("karaf.etc", previous);
            }
        }
    }

    /** An HTTP request exposing an X-Forwarded-For header and a socket (remote) address. */
    private static HttpServletRequest requestWith(String xForwardedFor, String remoteAddr) {
        return (HttpServletRequest) Proxy.newProxyInstance(
                MfaLoginGateFilterTest.class.getClassLoader(),
                new Class<?>[]{HttpServletRequest.class},
                (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "getHeader":
                            return "X-Forwarded-For".equals(args[0]) ? xForwardedFor : null;
                        case "getRemoteAddr":
                            return remoteAddr;
                        case "getRequestURI":
                            return "/cms/login";
                        case "getContextPath":
                            return "";
                        default:
                            return null;
                    }
                });
    }

    /** A bare GET /cms/login with no site context and a non-whitelisted socket address. */
    private static HttpServletRequest loginRequest() {
        return (HttpServletRequest) Proxy.newProxyInstance(
                MfaLoginGateFilterTest.class.getClassLoader(),
                new Class<?>[]{HttpServletRequest.class},
                (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "getRequestURI":
                            return "/cms/login";
                        case "getContextPath":
                            return "";
                        case "getRemoteAddr":
                            return "198.51.100.23";
                        default:
                            return null;
                    }
                });
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

    private static MfaLoginGateFilter gateWith(String enforcedFactors, MfaSiteProvider... providers) {
        return gateWith(enforcedFactors, null, providers);
    }

    private static MfaLoginGateFilter gateWith(String enforcedFactors, String globalLoginUrl,
                                               MfaSiteProvider... providers) {
        MfaLoginGateFilter gate = new MfaLoginGateFilter();
        MfaGlobalPolicy policy = new MfaGlobalPolicy();
        Map<String, Object> props = new HashMap<>();
        props.put("enforcedFactors", enforcedFactors);
        policy.activate(props);
        gate.setGlobalPolicy(policy);
        MfaLoginLogoutProvider urls = new MfaLoginLogoutProvider();
        Map<String, Object> urlProps = new HashMap<>();
        if (globalLoginUrl != null) {
            urlProps.put(MfaLoginLogoutProvider.CONFIG_LOGIN_URL, globalLoginUrl);
        }
        urls.activate(urlProps);
        gate.setLoginLogoutProvider(urls);
        for (MfaSiteProvider p : providers) {
            gate.bindSiteProvider(p);
        }
        return gate;
    }

    private static MfaSiteProvider provider(String type, boolean enabledForSite, boolean anySiteEnabled,
                                            boolean throwing) {
        return new MfaSiteProvider() {
            @Override
            public String getFactorType() {
                return type;
            }

            @Override
            public boolean isEnabledForSite(String siteKey) {
                if (throwing) {
                    throw new IllegalStateException("backend down");
                }
                return enabledForSite;
            }

            @Override
            public boolean isAnySiteEnabled() {
                if (throwing) {
                    throw new IllegalStateException("backend down");
                }
                return anySiteEnabled;
            }

            @Override
            public boolean isConfiguredForUser(String userId) {
                return false;
            }
        };
    }
}
