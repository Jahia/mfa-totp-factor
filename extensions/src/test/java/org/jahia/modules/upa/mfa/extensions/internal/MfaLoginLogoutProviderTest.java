package org.jahia.modules.upa.mfa.extensions.internal;

import org.jahia.modules.upa.mfa.extensions.MfaSiteConfigService;
import org.junit.Test;

import javax.servlet.http.HttpServletRequest;
import java.lang.reflect.Proxy;
import java.util.Dictionary;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;

import static org.jahia.modules.upa.mfa.extensions.MfaUrls.isSafeGlobalRedirectUrl;
import static org.jahia.modules.upa.mfa.extensions.internal.MfaLoginLogoutProvider.appendRedirect;
import static org.jahia.modules.upa.mfa.extensions.internal.MfaLoginLogoutProvider.chooseUrl;
import static org.jahia.modules.upa.mfa.extensions.internal.MfaLoginLogoutProvider.redirectTarget;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for {@link MfaLoginLogoutProvider}.
 * <p>
 * Two things are covered without a JCR / OSGi container:
 * <ul>
 *   <li>the global-config fallback exposed via {@code getLoginUrl(null)} / {@code getLogoutUrl(null)}
 *       (a {@code null} request can't resolve a site, so the global default is what surfaces);</li>
 *   <li>the per-site-vs-global precedence rule, via the {@code chooseUrl} helper.</li>
 * </ul>
 * The full request → site → per-site-URL path (per-site URLs surfaced through the registered
 * {@code MfaSiteProvider}s) is exercised end-to-end by the Cypress GraphQL round-trip
 * ({@code graphQL.totp.adminPolicy}), which stores per-site URLs and reads them back.
 */
public class MfaLoginLogoutProviderTest {

    private static MfaLoginLogoutProvider providerWith(String loginUrl, String logoutUrl) {
        MfaLoginLogoutProvider provider = new MfaLoginLogoutProvider();
        Map<String, Object> props = new HashMap<>();
        if (loginUrl != null) {
            props.put(MfaLoginLogoutProvider.CONFIG_LOGIN_URL, loginUrl);
        }
        if (logoutUrl != null) {
            props.put(MfaLoginLogoutProvider.CONFIG_LOGOUT_URL, logoutUrl);
        }
        provider.activate(props);
        return provider;
    }

    @Test
    public void alwaysWillingToProvideAUrl() {
        // Both "has custom URL" flags must be a stable true so the provider is registered and
        // consulted; the real decision happens per request in the URL getters — see class javadoc.
        MfaLoginLogoutProvider provider = new MfaLoginLogoutProvider();
        provider.activate(null);
        assertTrue(provider.hasCustomLoginUrl());
        assertTrue(provider.hasCustomLogoutUrl());
    }

    @Test
    public void noGlobalConfigYieldsNullForNullRequest() {
        MfaLoginLogoutProvider provider = new MfaLoginLogoutProvider();
        provider.activate(null);
        assertNull(provider.getLoginUrl(null));
        assertNull(provider.getLogoutUrl(null));
    }

    @Test
    public void blankGlobalUrlsYieldNull() {
        MfaLoginLogoutProvider provider = providerWith("   ", "");
        assertNull(provider.getLoginUrl(null));
        assertNull(provider.getLogoutUrl(null));
    }

    @Test
    public void globalLoginUrlIsReturnedAndTrimmed() {
        MfaLoginLogoutProvider provider = providerWith("  /sites/mySite/login.html  ", null);
        assertEquals("/sites/mySite/login.html", provider.getLoginUrl(null));
        assertNull("logout left unset falls through to null", provider.getLogoutUrl(null));
    }

    @Test
    public void globalLoginAndLogoutAreIndependent() {
        MfaLoginLogoutProvider provider = providerWith(null, "/sites/mySite/logout.html");
        assertNull(provider.getLoginUrl(null));
        assertEquals("/sites/mySite/logout.html", provider.getLogoutUrl(null));
    }

    @Test
    public void reconfigurationViaModifiedRefreshesGlobalUrls() {
        MfaLoginLogoutProvider provider = providerWith("/sites/a/login.html", "/sites/a/logout.html");
        assertEquals("/sites/a/login.html", provider.getLoginUrl(null));

        Map<String, Object> updated = new HashMap<>();
        updated.put(MfaLoginLogoutProvider.CONFIG_LOGIN_URL, "/sites/b/login.html");
        provider.activate(updated);

        assertEquals("/sites/b/login.html", provider.getLoginUrl(null));
        assertNull("logout cleared on reconfigure", provider.getLogoutUrl(null));
    }

    @Test
    public void chooseUrlPrefersPerSiteOverGlobal() {
        assertEquals("/per-site", chooseUrl("/per-site", "/global"));
        assertEquals("/global", chooseUrl(null, "/global"));
        assertEquals("/global", chooseUrl("   ", "/global"));
        assertEquals("/global", chooseUrl("", "  /global  ".trim()));
        assertNull(chooseUrl(null, null));
        assertNull(chooseUrl("  ", "   "));
    }

    @Test
    public void chooseUrlAllowsHttpAbsoluteGlobalForExternalSso() {
        assertEquals("https://sso.example.com/login", chooseUrl(null, "https://sso.example.com/login"));
        assertEquals("http://sso.example.com/login", chooseUrl(null, "http://sso.example.com/login"));
    }

    @Test
    public void chooseUrlRejectsDangerousGlobalSchemeOnTheReadPath() {
        // A hand-edited global .cfg must not be able to inject javascript:/data:/vbscript:.
        assertNull(chooseUrl(null, "javascript:alert(1)"));
        assertNull(chooseUrl(null, "data:text/html;base64,x"));
        assertNull(chooseUrl(null, "vbscript:msgbox"));
        // protocol-relative is an open-redirect vector → also rejected.
        assertNull(chooseUrl(null, "//evil.example"));
    }

    @Test
    public void isSafeGlobalUrlClassifies() {
        assertTrue(isSafeGlobalRedirectUrl("/sites/a/login.html"));
        assertTrue(isSafeGlobalRedirectUrl("https://sso.example.com/login"));
        assertTrue(isSafeGlobalRedirectUrl("http://sso.example.com/login"));
        assertFalse(isSafeGlobalRedirectUrl("javascript:alert(1)"));
        assertFalse(isSafeGlobalRedirectUrl("DATA:text/html,x"));
        assertFalse(isSafeGlobalRedirectUrl("//evil.example"));
        assertFalse("an http(s) URL with no host is not well-formed", isSafeGlobalRedirectUrl("http://"));
        assertFalse(isSafeGlobalRedirectUrl(null));
        assertFalse(isSafeGlobalRedirectUrl("   "));
    }

    // --- redirect propagation ---------------------------------------------------------------

    /** Minimal request fake: URI + query + parameters + dispatch attributes, empty context path. */
    private static HttpServletRequest request(String uri, String query, Map<String, String> params,
                                              Map<String, Object> attributes) {
        return (HttpServletRequest) Proxy.newProxyInstance(
                MfaLoginLogoutProviderTest.class.getClassLoader(),
                new Class<?>[]{HttpServletRequest.class},
                (proxy, method, args) -> {
                    switch (method.getName()) {
                        case "getRequestURI":
                            return uri;
                        case "getQueryString":
                            return query;
                        case "getContextPath":
                            return "";
                        case "getParameter":
                            return params == null ? null : params.get(args[0]);
                        case "getAttribute":
                            return attributes == null ? null : attributes.get(args[0]);
                        default:
                            return null;
                    }
                });
    }

    private static HttpServletRequest request(String uri, String query, Map<String, String> params) {
        return request(uri, query, params, null);
    }

    @Test
    public void redirectTargetIsTheRequestedPageWithItsQueryString() {
        assertEquals("/sites/mySite/private.html",
                redirectTarget(request("/sites/mySite/private.html", null, null)));
        assertEquals("/sites/mySite/private.html?tab=2",
                redirectTarget(request("/sites/mySite/private.html", "tab=2", null)));
    }

    @Test
    public void explicitRedirectParameterWinsOverTheRequestUri() {
        // Jahia core and templates pass ?redirect= on /cms/login|logout links: it must survive
        // the hop to the custom page instead of being replaced by the auth endpoint's own URI.
        Map<String, String> params = new HashMap<>();
        params.put("redirect", "/sites/mySite/here.html");
        assertEquals("/sites/mySite/here.html", redirectTarget(request("/cms/login", null, params)));
    }

    @Test
    public void unsafeExplicitRedirectParameterIsDropped() {
        Map<String, String> params = new HashMap<>();
        params.put("redirect", "https://evil.example/phish");
        assertNull("open-redirect guard", redirectTarget(request("/cms/login", null, params)));
        params.put("redirect", "//evil.example");
        assertNull(redirectTarget(request("/cms/login", null, params)));
    }

    @Test
    public void authEndpointsAreNeverARedirectTarget() {
        assertNull(redirectTarget(request("/cms/login", null, null)));
        assertNull(redirectTarget(request("/cms/logout", "site=x", null)));
        assertNull(redirectTarget(request("/error", null, null)));
        assertNull(redirectTarget(null));
    }

    @Test
    public void moduleResourcesAreNeverARedirectTarget() {
        // config.logoutUrl/loginUrl are baked into the per-request jahiaUserEntries.js config
        // asset; at generation time the request IS that asset. Capturing it as the redirect
        // target stranded the user on the .js file after logout (the reported bug).
        assertNull(redirectTarget(
                request("/modules/jahia-user-entries/configs/jahiaUserEntries.js", "v=1782568469067", null)));
        assertNull(redirectTarget(request("/modules/graphql", null, null)));
    }

    @Test
    public void errorDispatchAttributeIsThePageThe401WasRaisedFor() {
        // Jahia's 401 handling FORWARDS to /error before consulting the providers: the page the
        // user asked for is in the standard ERROR dispatch attribute, not the request URI.
        Map<String, Object> attrs = new HashMap<>();
        attrs.put("javax.servlet.error.request_uri", "/jahia/dashboard");
        assertEquals("/jahia/dashboard", redirectTarget(request("/error", null, null, attrs)));
    }

    @Test
    public void forwardDispatchAttributesKeepTheOriginalUriAndQuery() {
        Map<String, Object> attrs = new HashMap<>();
        attrs.put("javax.servlet.forward.request_uri", "/sites/mySite/private.html");
        attrs.put("javax.servlet.forward.query_string", "tab=2");
        assertEquals("/sites/mySite/private.html?tab=2",
                redirectTarget(request("/cms/render/live/en/sites/mySite/private.html", null, null, attrs)));
    }

    @Test
    public void loginUrlCarriesTheOriginalTargetAsEncodedRedirectParam() {
        MfaLoginLogoutProvider provider = providerWith("/sites/mySite/login.html", null);
        assertEquals("/sites/mySite/login.html?redirect=%2Fsites%2FmySite%2Fprivate.html%3Ftab%3D2",
                provider.getLoginUrl(request("/sites/mySite/private.html", "tab=2", null)));
    }

    @Test
    public void logoutUrlCarriesTheCurrentPageAsRedirectParam() {
        MfaLoginLogoutProvider provider = providerWith(null, "/sites/mySite/logout.html");
        assertEquals("/sites/mySite/logout.html?redirect=%2Fsites%2FmySite%2Fpage.html",
                provider.getLogoutUrl(request("/sites/mySite/page.html", null, null)));
    }

    @Test
    public void appendRedirectUsesAmpersandWhenTheUrlAlreadyHasAQuery() {
        assertEquals("/login.html?foo=1&redirect=%2Fpage.html",
                appendRedirect("/login.html?foo=1", "/page.html"));
    }

    @Test
    public void appendRedirectSkipsSelfLoopAndHardcodedRedirect() {
        // Rendering the login page itself must not produce redirect=<login page>.
        assertEquals("/login.html", appendRedirect("/login.html", "/login.html"));
        assertEquals("/login.html", appendRedirect("/login.html", "/login.html?foo=1"));
        // An operator-hardcoded redirect param is authoritative.
        assertEquals("/login.html?redirect=%2Fhome.html",
                appendRedirect("/login.html?redirect=%2Fhome.html", "/page.html"));
        // No URL / no target → unchanged.
        assertNull(appendRedirect(null, "/page.html"));
        assertEquals("/login.html", appendRedirect("/login.html", null));
        assertEquals("/login.html", appendRedirect("/login.html", " "));
    }

    // --- per-site URL from the file-backed config service ------------------------------------

    /** Build a config service populated as if FileInstall delivered one site's {@code .cfg}. */
    private static MfaSiteConfigService configServiceWith(String siteKey, String loginUrl, String logoutUrl) {
        MfaSiteConfigService service = new MfaSiteConfigService();
        Dictionary<String, Object> props = new Hashtable<>();
        props.put("siteKey", siteKey);
        if (loginUrl != null) {
            props.put("loginUrl", loginUrl);
        }
        if (logoutUrl != null) {
            props.put("logoutUrl", logoutUrl);
        }
        service.updated("pid-" + siteKey, props);
        return service;
    }

    @Test
    public void perSiteUrlFromConfigServiceWinsOverGlobalAndCarriesRedirect() {
        MfaLoginLogoutProvider provider = providerWith("/global/login.html", null);
        provider.setSiteConfigService(configServiceWith("digitall", "/login.html", null));
        Map<String, Object> attrs = new HashMap<>();
        attrs.put("siteKey", "digitall"); // resolveSiteKey reads the request 'siteKey' attribute
        assertEquals("/login.html?redirect=%2Fstart",
                provider.getLoginUrl(request("/start", null, null, attrs)));
    }

    @Test
    public void unsafePerSiteUrlFromAHandEditedCfgIsIgnoredAndFallsBackToGlobal() {
        MfaLoginLogoutProvider provider = providerWith("/global/login.html", null);
        provider.setSiteConfigService(configServiceWith("digitall", "https://evil.example/x", null));
        Map<String, Object> attrs = new HashMap<>();
        attrs.put("siteKey", "digitall");
        assertEquals("/global/login.html?redirect=%2Fstart",
                provider.getLoginUrl(request("/start", null, null, attrs)));
    }
}
