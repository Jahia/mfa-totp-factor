package org.jahia.modules.upa.mfa.totp;

import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for {@link MfaTotpLoginLogoutProvider} config parsing and the
 * "inert until configured" contract. No JCR / OSGi container is required.
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
    public void disabledByDefaultWhenNoConfig() {
        MfaTotpLoginLogoutProvider provider = new MfaTotpLoginLogoutProvider();
        provider.activate(null);
        assertFalse("no config => no custom login URL", provider.hasCustomLoginUrl());
        assertFalse("no config => no custom logout URL", provider.hasCustomLogoutUrl());
        assertNull(provider.getLoginUrl(null));
        assertNull(provider.getLogoutUrl(null));
    }

    @Test
    public void blankUrlsKeepProviderInert() {
        MfaTotpLoginLogoutProvider provider = providerWith("   ", "");
        assertFalse("blank login URL => inert", provider.hasCustomLoginUrl());
        assertFalse("empty logout URL => inert", provider.hasCustomLogoutUrl());
        assertNull(provider.getLoginUrl(null));
        assertNull(provider.getLogoutUrl(null));
    }

    @Test
    public void configuredLoginUrlIsAdvertisedAndTrimmed() {
        MfaTotpLoginLogoutProvider provider = providerWith("  /sites/mySite/login.html  ", null);
        assertTrue(provider.hasCustomLoginUrl());
        assertEquals("/sites/mySite/login.html", provider.getLoginUrl(null));
        assertFalse("logout left unset stays inert", provider.hasCustomLogoutUrl());
    }

    @Test
    public void loginAndLogoutAreIndependent() {
        MfaTotpLoginLogoutProvider provider = providerWith(null, "/sites/mySite/logout.html");
        assertFalse(provider.hasCustomLoginUrl());
        assertTrue(provider.hasCustomLogoutUrl());
        assertEquals("/sites/mySite/logout.html", provider.getLogoutUrl(null));
    }

    @Test
    public void reconfigurationViaModifiedRefreshesUrls() {
        MfaTotpLoginLogoutProvider provider = providerWith("/sites/a/login.html", "/sites/a/logout.html");
        assertEquals("/sites/a/login.html", provider.getLoginUrl(null));

        // @Modified re-invokes activate with the new properties — both URLs swap live.
        Map<String, Object> updated = new HashMap<>();
        updated.put(MfaTotpLoginLogoutProvider.CONFIG_LOGIN_URL, "/sites/b/login.html");
        provider.activate(updated);

        assertEquals("/sites/b/login.html", provider.getLoginUrl(null));
        assertFalse("logout cleared on reconfigure", provider.hasCustomLogoutUrl());
        assertNull(provider.getLogoutUrl(null));
    }
}
