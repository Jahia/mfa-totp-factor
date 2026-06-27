package org.jahia.modules.upa.mfa.extensions.internal;

import org.jahia.modules.upa.mfa.extensions.MfaGlobalPolicy;
import org.jahia.modules.upa.mfa.extensions.MfaSiteConfigService;
import org.jahia.modules.upa.mfa.extensions.MfaSiteProvider;
import org.junit.Test;

import javax.servlet.http.HttpServletRequest;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.jahia.modules.upa.mfa.extensions.internal.MfaLoginGateDecision.isCmsLogin;
import static org.jahia.modules.upa.mfa.extensions.internal.MfaLoginGateDecision.isIpLiteral;
import static org.jahia.modules.upa.mfa.extensions.internal.MfaLoginGateDecision.isWhitelisted;
import static org.jahia.modules.upa.mfa.extensions.internal.MfaLoginGateDecision.parseWhitelist;
import static org.jahia.modules.upa.mfa.extensions.internal.MfaLoginGateDecision.resolveClientIp;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * The shared /cms/login gating decision: whitelist matching (the client IP - first X-Forwarded-For
 * entry when trusted - must match a configured address or CIDR block; never DNS-resolved, mixed
 * IPv4/IPv6 never match), the global-policy &cap; per-site activation gating, the X-Forwarded-For
 * trust switch, the startup fail-CLOSED readiness guard, and login-URL resolution.
 */
public class MfaLoginGateDecisionTest {

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
        MfaLoginGateDecision decision = decisionWith("", provider("totp", true, true, false));
        assertFalse(decision.anyEnforcesForSite("siteA"));
        assertFalse(decision.computeAnySiteEnforcing());
    }

    @Test
    public void notGatedWhenEnabledFactorIsNotEnforced() {
        MfaLoginGateDecision decision = decisionWith("webauthn", provider("totp", true, true, false));
        assertFalse(decision.anyEnforcesForSite("siteA"));
        assertFalse(decision.computeAnySiteEnforcing());
    }

    @Test
    public void gatedWhenAnEnforcedFactorIsEnabledOnTheSite() {
        MfaLoginGateDecision decision = decisionWith("totp,webauthn",
                provider("totp", false, false, false),
                provider("webauthn", true, true, false));
        assertTrue(decision.anyEnforcesForSite("siteA"));
        assertTrue(decision.computeAnySiteEnforcing());
    }

    @Test
    public void notGatedWhenEnforcedFactorsAreDisabledOnEverySite() {
        MfaLoginGateDecision decision = decisionWith("totp", provider("totp", false, false, false));
        assertFalse(decision.anyEnforcesForSite("siteA"));
        assertFalse(decision.computeAnySiteEnforcing());
    }

    @Test
    public void throwingProviderFailsClosed() {
        MfaLoginGateDecision decision = decisionWith("totp", provider("totp", true, true, true));
        assertTrue("an unanswerable provider must block (fail closed)", decision.anyEnforcesForSite("siteA"));
        assertTrue(decision.computeAnySiteEnforcing());
    }

    @Test
    public void isGated_falseWhenEnforcementInactive() {
        MfaLoginGateDecision decision = decisionWith("", provider("totp", true, true, false));
        assertFalse(decision.isGated(loginRequest()));
    }

    @Test
    public void isGated_trueWhenAnySiteEnforcesAndNoSiteContext() {
        MfaLoginGateDecision decision = decisionWith("totp", provider("totp", true, true, false));
        assertTrue(decision.isGated(loginRequest()));
    }

    // --- isCmsLogin recognition ----------------------------------------------------------

    @Test
    public void isCmsLoginRecognizesTheDefaultEndpoint() {
        assertTrue(isCmsLogin("/cms/login", ""));
        assertTrue("a query string does not change the endpoint", isCmsLogin("/cms/login?site=x", ""));
        assertTrue("context path is stripped", isCmsLogin("/ctx/cms/login", "/ctx"));
        assertFalse(isCmsLogin("/sites/mySite/login.html", ""));
        assertFalse(isCmsLogin("/cms/logout", ""));
        assertFalse(isCmsLogin(null, ""));
    }

    // --- Login URL resolution ------------------------------------------------------------

    @Test
    public void resolveDistinctLoginUrl_returnsConfiguredCustomPage() {
        MfaLoginGateDecision decision = decisionWith("totp", "/sites/mySite/login.html",
                provider("totp", true, true, false));
        assertEquals("/sites/mySite/login.html", decision.resolveDistinctLoginUrl(loginRequest()));
        assertFalse(decision.isCmsLoginConfigured(loginRequest()));
    }

    @Test
    public void resolveDistinctLoginUrl_nullWhenCmsLoginConfigured() {
        MfaLoginGateDecision decision = decisionWith("totp", "/cms/login", provider("totp", true, true, false));
        assertNull("redirecting to /cms/login would loop", decision.resolveDistinctLoginUrl(loginRequest()));
        assertTrue(decision.isCmsLoginConfigured(loginRequest()));
    }

    @Test
    public void resolveDistinctLoginUrl_nullWhenNothingConfigured() {
        MfaLoginGateDecision decision = decisionWith("totp", (String) null, provider("totp", true, true, false));
        assertNull(decision.resolveDistinctLoginUrl(loginRequest()));
        assertFalse(decision.isCmsLoginConfigured(loginRequest()));
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
    public void isClientWhitelisted_forgedHeaderIgnoredWhenNotTrusted() {
        // Whitelist the proxy IP; an attacker forges X-Forwarded-For: <whitelisted> from a
        // non-whitelisted socket. With trustForwardedFor=false the decision must NOT whitelist them.
        MfaLoginGateDecision decision = decisionWith("totp", (String) null, provider("totp", true, true, false));
        Map<String, Object> props = new HashMap<>();
        props.put("enforcedFactors", "totp");
        props.put(MfaLoginGateDecision.CONFIG_GATE_WHITELIST, "203.0.113.9");
        props.put(MfaLoginGateDecision.CONFIG_TRUST_FORWARDED_FOR, "false");
        decision.activate(props);
        assertFalse("forged XFF must be ignored",
                decision.isClientWhitelisted(requestWith("203.0.113.9", "198.51.100.23")));
    }

    @Test
    public void isClientWhitelisted_trustedHeaderMatchesWhitelist() {
        MfaLoginGateDecision decision = decisionWith("totp", (String) null, provider("totp", true, true, false));
        Map<String, Object> props = new HashMap<>();
        props.put("enforcedFactors", "totp");
        props.put(MfaLoginGateDecision.CONFIG_GATE_WHITELIST, "203.0.113.9");
        decision.activate(props); // trustForwardedFor defaults to true
        assertTrue(decision.isClientWhitelisted(requestWith("203.0.113.9", "198.51.100.23")));
    }

    // --- Startup fail-CLOSED while the per-site config service is not ready --------------------

    @Test
    public void noSiteContext_failsClosedWhileConfigServiceNotReady() {
        // Enforcement active, no site context, and the per-site config service has NOT finished its
        // eager scan: the no-site path must fail CLOSED (block) rather than report "not enforcing".
        MfaLoginGateDecision decision = decisionWith("totp", (String) null, provider("totp", true, false, false));
        decision.setSiteConfigService(new MfaSiteConfigService()); // never activated → isReady()==false
        assertTrue("not-ready + enforcement active must gate", decision.isGated(loginRequest()));
    }

    @Test
    public void noSiteContext_standsDownWhenConfigServiceReadyWithNoSites() throws Exception {
        // Once the per-site config service HAS activated (isReady()==true) and no site enforces, the
        // readiness guard must NOT keep over-blocking. This proves the guard blocks ONLY during the
        // startup window, not whenever a service is wired.
        MfaLoginGateDecision decision = decisionWith("totp", (String) null, provider("totp", false, false, false));
        decision.setSiteConfigService(activatedEmptyConfigService());
        assertFalse("ready + no site enforcing → not gated", decision.isGated(loginRequest()));
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
                MfaLoginGateDecisionTest.class.getClassLoader(),
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
    static HttpServletRequest loginRequest() {
        return (HttpServletRequest) Proxy.newProxyInstance(
                MfaLoginGateDecisionTest.class.getClassLoader(),
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

    static MfaLoginGateDecision decisionWith(String enforcedFactors, MfaSiteProvider... providers) {
        return decisionWith(enforcedFactors, null, providers);
    }

    static MfaLoginGateDecision decisionWith(String enforcedFactors, String globalLoginUrl,
                                             MfaSiteProvider... providers) {
        MfaLoginGateDecision decision = new MfaLoginGateDecision();
        MfaGlobalPolicy policy = new MfaGlobalPolicy();
        Map<String, Object> props = new HashMap<>();
        props.put("enforcedFactors", enforcedFactors);
        policy.activate(props);
        decision.setGlobalPolicy(policy);
        MfaLoginLogoutProvider urls = new MfaLoginLogoutProvider();
        Map<String, Object> urlProps = new HashMap<>();
        if (globalLoginUrl != null) {
            urlProps.put(MfaLoginLogoutProvider.CONFIG_LOGIN_URL, globalLoginUrl);
        }
        urls.activate(urlProps);
        decision.setLoginLogoutProvider(urls);
        for (MfaSiteProvider p : providers) {
            decision.bindSiteProvider(p);
        }
        return decision;
    }

    static MfaSiteProvider provider(String type, boolean enabledForSite, boolean anySiteEnabled,
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
