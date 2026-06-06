package org.jahia.modules.upa.mfa.extensions.internal;

import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.jahia.modules.upa.mfa.extensions.internal.MfaLoginLogoutProvider.chooseUrl;
import static org.junit.Assert.assertEquals;
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
}
