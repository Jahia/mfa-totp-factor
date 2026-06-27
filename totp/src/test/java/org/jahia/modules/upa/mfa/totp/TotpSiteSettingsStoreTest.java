package org.jahia.modules.upa.mfa.totp;

import org.jahia.modules.upa.mfa.extensions.MfaSiteConfigService;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.util.Collections;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

/**
 * Unit tests for {@link TotpSiteSettingsStore}, backed by a real {@link MfaSiteConfigService} over a
 * {@link TemporaryFolder} used as {@code karaf.etc} (no running container). Mirrors the JUnit4 style
 * of {@code MfaSiteConfigServiceTest}.
 * <p>
 * The login/logout URLs are factor-agnostic and shared in the same per-site {@code .cfg}, so a TOTP
 * write that does NOT carry a given URL (its provided flag is {@code false}) must be a true PARTIAL
 * update that preserves that previously stored URL - including when only the SIBLING URL is written,
 * which must not erase the omitted one. This is the data-loss fix under test.
 */
public class TotpSiteSettingsStoreTest {

    private static final String SITE_KEY = "digitall";

    @Rule
    public TemporaryFolder etc = new TemporaryFolder();

    private TotpSiteSettingsStore store;

    @Before
    public void setUp() {
        System.setProperty("karaf.etc", etc.getRoot().getAbsolutePath());
        store = new TotpSiteSettingsStore();
        store.setSiteConfigService(new MfaSiteConfigService());
    }

    @After
    public void tearDown() {
        System.clearProperty("karaf.etc");
    }

    private static TotpSiteSettingsStore.TotpSiteSettings withUrls(boolean enabled, String loginUrl, String logoutUrl) {
        return new TotpSiteSettingsStore.TotpSiteSettings(
                enabled, Collections.emptyList(), loginUrl, logoutUrl, true, true);
    }

    private static TotpSiteSettingsStore.TotpSiteSettings urlsOmitted(boolean enabled) {
        return new TotpSiteSettingsStore.TotpSiteSettings(
                enabled, Collections.emptyList(), null, null, false, false);
    }

    /** Provide ONLY the login URL; the logout URL is omitted (its provided flag is false). */
    private static TotpSiteSettingsStore.TotpSiteSettings onlyLoginUrl(boolean enabled, String loginUrl) {
        return new TotpSiteSettingsStore.TotpSiteSettings(
                enabled, Collections.emptyList(), loginUrl, null, true, false);
    }

    /** Provide ONLY the logout URL; the login URL is omitted (its provided flag is false). */
    private static TotpSiteSettingsStore.TotpSiteSettings onlyLogoutUrl(boolean enabled, String logoutUrl) {
        return new TotpSiteSettingsStore.TotpSiteSettings(
                enabled, Collections.emptyList(), null, logoutUrl, false, true);
    }

    @Test
    public void omittedUrlsPreservePreviouslyStoredLoginUrl() throws Exception {
        // Arrange: a first save sets a login URL (URLs provided).
        store.save(SITE_KEY, withUrls(true, "/login.html", null));
        assertEquals("/login.html", store.load(SITE_KEY).getLoginUrl());

        // Act: a second save toggles enabled and OMITS the URLs (partial update).
        store.save(SITE_KEY, urlsOmitted(false));

        // Assert: the previously stored login URL survives, only the factor slice changed.
        TotpSiteSettingsStore.TotpSiteSettings reloaded = store.load(SITE_KEY);
        assertEquals("loginUrl must survive an URL-omitting save", "/login.html", reloaded.getLoginUrl());
        assertFalse("enabled toggle must apply", reloaded.isEnabled());
    }

    @Test
    public void providingOnlyLoginUrlPreservesTheSiblingLogoutUrl() throws Exception {
        // Arrange: store BOTH URLs.
        store.save(SITE_KEY, withUrls(true, "/login.html", "/logout.html"));
        assertEquals("/login.html", store.load(SITE_KEY).getLoginUrl());
        assertEquals("/logout.html", store.load(SITE_KEY).getLogoutUrl());

        // Act: save providing ONLY the login URL (logout omitted).
        store.save(SITE_KEY, onlyLoginUrl(true, "/new-login.html"));

        // Assert: login updated AND the sibling logout URL survives (no all-or-nothing erase).
        TotpSiteSettingsStore.TotpSiteSettings reloaded = store.load(SITE_KEY);
        assertEquals("loginUrl must update", "/new-login.html", reloaded.getLoginUrl());
        assertEquals("sibling logoutUrl must survive a login-only save", "/logout.html", reloaded.getLogoutUrl());
    }

    @Test
    public void providingOnlyLogoutUrlPreservesTheSiblingLoginUrl() throws Exception {
        // Arrange: store BOTH URLs.
        store.save(SITE_KEY, withUrls(true, "/login.html", "/logout.html"));
        assertEquals("/login.html", store.load(SITE_KEY).getLoginUrl());
        assertEquals("/logout.html", store.load(SITE_KEY).getLogoutUrl());

        // Act: save providing ONLY the logout URL (login omitted).
        store.save(SITE_KEY, onlyLogoutUrl(true, "/new-logout.html"));

        // Assert: logout updated AND the sibling login URL survives (no all-or-nothing erase).
        TotpSiteSettingsStore.TotpSiteSettings reloaded = store.load(SITE_KEY);
        assertEquals("logoutUrl must update", "/new-logout.html", reloaded.getLogoutUrl());
        assertEquals("sibling loginUrl must survive a logout-only save", "/login.html", reloaded.getLoginUrl());
    }

    @Test
    public void emptyStringLoginUrlClearsTheStoredValue() throws Exception {
        // Arrange: a stored login URL.
        store.save(SITE_KEY, withUrls(true, "/login.html", null));
        assertEquals("/login.html", store.load(SITE_KEY).getLoginUrl());

        // Act: an explicit clear - empty string is provided (loginUrl provided flag true), validated to null.
        store.save(SITE_KEY, withUrls(true, "", null));

        // Assert: the URL is cleared.
        assertNull("empty-string loginUrl must clear the stored value", store.load(SITE_KEY).getLoginUrl());
    }

    @Test
    public void invalidUrlIsRejected() {
        // The open-redirect guard rejects a non server-relative path.
        final TotpSiteSettingsStore.TotpSiteSettings settings = withUrls(true, "http://evil", null);
        assertThrows(IllegalArgumentException.class, () -> store.save(SITE_KEY, settings));
    }

    @Test
    public void loadWhenAbsentReturnsDisabledEmpty() {
        TotpSiteSettingsStore.TotpSiteSettings settings = store.load("never-configured");
        assertFalse("absent site must be disabled", settings.isEnabled());
        assertTrue("absent site must have no enabled groups", settings.getEnabledGroups().isEmpty());
        assertNull("absent site must have no login URL", settings.getLoginUrl());
        assertNull("absent site must have no logout URL", settings.getLogoutUrl());
    }
}
