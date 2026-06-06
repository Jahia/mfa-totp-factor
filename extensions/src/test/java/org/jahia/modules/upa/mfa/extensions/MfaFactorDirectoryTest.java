package org.jahia.modules.upa.mfa.extensions;

import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * {@link MfaFactorDirectory#configuredFactorsForUser}: the list driving the login UI's factor
 * chooser — only factors the user configured AND may use on the site, in provider registration
 * order, deduplicated.
 */
public class MfaFactorDirectoryTest {

    private static final String USER = "alice";
    private static final String SITE = "siteA";

    private MfaFactorDirectory directory;

    @Before
    public void setUp() {
        directory = new MfaFactorDirectory();
        MfaGlobalPolicy policy = new MfaGlobalPolicy();
        policy.activate(java.util.Collections.emptyMap());
        directory.setGlobalPolicy(policy);
    }

    private static MfaSiteProvider provider(String type, boolean configured, boolean enabledOnSite) {
        return new MfaSiteProvider() {
            @Override
            public String getFactorType() {
                return type;
            }

            @Override
            public boolean isEnabledForSite(String siteKey) {
                return enabledOnSite;
            }

            @Override
            public boolean isAnySiteEnabled() {
                return enabledOnSite;
            }

            @Override
            public boolean isConfiguredForUser(String userId) {
                return configured;
            }
        };
    }

    @Test
    public void onlyConfiguredFactorsAreListed() {
        directory.bindSiteProvider(provider("totp", false, true));
        directory.bindSiteProvider(provider("webauthn", true, true));
        assertEquals(Arrays.asList("webauthn"), directory.configuredFactorsForUser(USER, SITE));
    }

    @Test
    public void factorDisabledOnTheSiteIsExcluded() {
        // Configured but disabled on this site: it would skip at prepare anyway — offering it
        // in the chooser would recreate the picked-totp-landed-on-webauthn confusion.
        directory.bindSiteProvider(provider("totp", true, false));
        directory.bindSiteProvider(provider("webauthn", true, true));
        assertEquals(Arrays.asList("webauthn"), directory.configuredFactorsForUser(USER, SITE));
    }

    @Test
    public void withoutSiteContextTheSiteCheckIsSkipped() {
        directory.bindSiteProvider(provider("totp", true, false));
        assertEquals(Arrays.asList("totp"), directory.configuredFactorsForUser(USER, null));
        assertEquals(Arrays.asList("totp"), directory.configuredFactorsForUser(USER, "  "));
    }

    @Test
    public void nothingConfiguredYieldsEmptyList() {
        directory.bindSiteProvider(provider("totp", false, true));
        directory.bindSiteProvider(provider("webauthn", false, true));
        assertTrue(directory.configuredFactorsForUser(USER, SITE).isEmpty());
    }

    @Test
    public void duplicateProviderTypesAreListedOnce() {
        directory.bindSiteProvider(provider("totp", true, true));
        directory.bindSiteProvider(provider("totp", true, true));
        List<String> result = directory.configuredFactorsForUser(USER, SITE);
        assertEquals(Arrays.asList("totp"), result);
    }
}
