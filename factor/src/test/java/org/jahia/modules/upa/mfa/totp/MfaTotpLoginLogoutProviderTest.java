package org.jahia.modules.upa.mfa.totp;

import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.jahia.modules.upa.mfa.totp.MfaTotpLoginLogoutProvider.chooseUrl;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for {@link MfaTotpLoginLogoutProvider}.
 * <p>
 * Two things are covered without a JCR / OSGi container:
 * <ul>
 *   <li>the global-config fallback exposed via {@code getLoginUrl(null)} / {@code getLogoutUrl(null)}
 *       (a {@code null} request can't resolve a site, so the global default is what surfaces);</li>
 *   <li>the per-site-vs-global precedence rule, via the {@code chooseUrl} helper.</li>
 * </ul>
 * The full request → site → per-site-URL path is exercised end-to-end by the Cypress GraphQL
 * round-trip ({@code graphQL.totp.adminPolicy}), which stores per-site URLs and reads them back.
 */
public class MfaTotpLoginLogoutProviderTest {

    private static MfaTotpLoginLogoutProvider providerWith(String loginUrl, String logoutUrl) {
        MfaTotpLoginLogoutProvider provider = new MfaTotpLoginLogoutProvider();
        Map<String, Object> props = new HashMap<>();
        if (loginUrl != null) {
            props.put(MfaTotpLoginLogoutProvider.CONFIG_LOGIN_URL, loginUrl);
        }
        if (logoutUrl != null) {
            props.put(MfaTotpLoginLogoutProvider.CONFIG_LOGOUT_URL, logoutUrl);
        }
        provider.activate(props);
        return provider;
    }

    @Test
    public void alwaysWillingToProvideAUrl() {
        // hasCustom*Url() must be a stable true so the provider is registered and consulted;
        // the real decision happens per-request in get*Url (see class javadoc).
        MfaTotpLoginLogoutProvider provider = new MfaTotpLoginLogoutProvider();
        provider.activate(null);
        assertTrue(provider.hasCustomLoginUrl());
        assertTrue(provider.hasCustomLogoutUrl());
    }

    @Test
    public void noGlobalConfigYieldsNullForNullRequest() {
        MfaTotpLoginLogoutProvider provider = new MfaTotpLoginLogoutProvider();
        provider.activate(null);
        assertNull(provider.getLoginUrl(null));
        assertNull(provider.getLogoutUrl(null));
    }

    @Test
    public void blankGlobalUrlsYieldNull() {
        MfaTotpLoginLogoutProvider provider = providerWith("   ", "");
        assertNull(provider.getLoginUrl(null));
        assertNull(provider.getLogoutUrl(null));
    }

    @Test
    public void globalLoginUrlIsReturnedAndTrimmed() {
        MfaTotpLoginLogoutProvider provider = providerWith("  /sites/mySite/login.html  ", null);
        assertEquals("/sites/mySite/login.html", provider.getLoginUrl(null));
        assertNull("logout left unset falls through to null", provider.getLogoutUrl(null));
    }

    @Test
    public void globalLoginAndLogoutAreIndependent() {
        MfaTotpLoginLogoutProvider provider = providerWith(null, "/sites/mySite/logout.html");
        assertNull(provider.getLoginUrl(null));
        assertEquals("/sites/mySite/logout.html", provider.getLogoutUrl(null));
    }

    @Test
    public void reconfigurationViaModifiedRefreshesGlobalUrls() {
        MfaTotpLoginLogoutProvider provider = providerWith("/sites/a/login.html", "/sites/a/logout.html");
        assertEquals("/sites/a/login.html", provider.getLoginUrl(null));

        Map<String, Object> updated = new HashMap<>();
        updated.put(MfaTotpLoginLogoutProvider.CONFIG_LOGIN_URL, "/sites/b/login.html");
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
