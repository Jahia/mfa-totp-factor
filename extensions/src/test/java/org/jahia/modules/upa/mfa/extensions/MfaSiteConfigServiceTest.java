package org.jahia.modules.upa.mfa.extensions;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Dictionary;
import java.util.Hashtable;
import java.util.Properties;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Unit tests for {@link MfaSiteConfigService} — the file-backed per-site MFA configuration factory.
 * Uses a {@link TemporaryFolder} as {@code karaf.etc} so the atomic-write path is exercised without
 * a running container.
 */
public class MfaSiteConfigServiceTest {

    private static final String FACTOR_TOTP = "totp";
    private static final String FACTOR_WEBAUTHN = "webauthn";

    @Rule
    public TemporaryFolder etc = new TemporaryFolder();

    private MfaSiteConfigService service;

    @Before
    public void setUp() {
        System.setProperty("karaf.etc", etc.getRoot().getAbsolutePath());
        service = new MfaSiteConfigService();
    }

    @After
    public void tearDown() {
        System.clearProperty("karaf.etc");
    }

    private static Dictionary<String, Object> props(String... keyValues) {
        Dictionary<String, Object> dict = new Hashtable<>();
        for (int i = 0; i < keyValues.length; i += 2) {
            dict.put(keyValues[i], keyValues[i + 1]);
        }
        return dict;
    }

    private Path cfgFile(String siteKey) {
        return etc.getRoot().toPath().resolve(MfaSiteConfigService.FACTORY_PID + "-" + siteKey + ".cfg");
    }

    // --- updated() / deleted() (FileInstall callbacks) --------------------------------------

    @Test
    public void updatedBuildsSnapshotKeyedBySiteKey() {
        service.updated("pid1", props(
                "siteKey", "digitall",
                "loginUrl", "/login.html",
                "totp.enabled", "true",
                "totp.enabledGroups", "editors, reviewers"));

        MfaSiteConfig config = service.getConfig("digitall");
        assertEquals("/login.html", config.getLoginUrl());
        assertTrue(config.isEnabled(FACTOR_TOTP));
        assertEquals(java.util.Arrays.asList("editors", "reviewers"), config.enabledGroups(FACTOR_TOTP));
        assertFalse(config.isEnabled(FACTOR_WEBAUTHN));
        assertTrue(service.anySiteEnabled(FACTOR_TOTP));
        assertFalse(service.anySiteEnabled(FACTOR_WEBAUTHN));
    }

    @Test
    public void updatedWithoutSiteKeyIsSkipped() {
        service.updated("pid1", props("loginUrl", "/login.html", "totp.enabled", "true"));
        assertEquals(MfaSiteConfig.EMPTY, service.getConfig("digitall"));
        assertFalse(service.anySiteEnabled(FACTOR_TOTP));
    }

    @Test
    public void updatedIsIdempotentAndReplacesOnChange() {
        service.updated("pid1", props("siteKey", "digitall", "totp.enabled", "true"));
        service.updated("pid1", props("siteKey", "digitall", "totp.enabled", "true"));
        assertTrue(service.getConfig("digitall").isEnabled(FACTOR_TOTP));

        service.updated("pid1", props("siteKey", "digitall", "totp.enabled", "false"));
        assertFalse(service.getConfig("digitall").isEnabled(FACTOR_TOTP));
    }

    @Test
    public void deletedEvictsTheSiteViaTheReversePidMap() {
        service.updated("pid1", props("siteKey", "digitall", "totp.enabled", "true"));
        assertTrue(service.getConfig("digitall").isEnabled(FACTOR_TOTP));

        service.deleted("pid1");
        assertEquals(MfaSiteConfig.EMPTY, service.getConfig("digitall"));
        service.deleted("unknown-pid"); // no-op, must not throw
    }

    @Test
    public void enabledGroupsCommaListIsTrimmedAndBlankEntriesDropped() {
        service.updated("pid1", props(
                "siteKey", "digitall",
                "totp.enabled", "true",
                "totp.enabledGroups", "a, ,  b ,,c,"));
        assertEquals(java.util.Arrays.asList("a", "b", "c"),
                service.getConfig("digitall").enabledGroups(FACTOR_TOTP));
    }

    // --- save() / delete() (admin writes) ---------------------------------------------------

    @Test
    public void saveWritesCfgFileAndUpdatesMapSynchronously() throws Exception {
        service.save("digitall", current ->
                current.withFactor(FACTOR_TOTP, true, java.util.Arrays.asList("editors")).withUrls("/login.html", null));

        // In-memory read-after-write is immediate (no FileInstall round-trip needed).
        MfaSiteConfig config = service.getConfig("digitall");
        assertTrue(config.isEnabled(FACTOR_TOTP));
        assertEquals("/login.html", config.getLoginUrl());

        // The .cfg exists and round-trips: feeding it back through updated() yields the same snapshot.
        assertTrue(Files.exists(cfgFile("digitall")));
        MfaSiteConfigService reloaded = new MfaSiteConfigService();
        reloaded.updated("pid-rt", loadAsDictionary(cfgFile("digitall")));
        MfaSiteConfig fromFile = reloaded.getConfig("digitall");
        assertTrue(fromFile.isEnabled(FACTOR_TOTP));
        assertEquals("/login.html", fromFile.getLoginUrl());
        assertEquals(java.util.Arrays.asList("editors"), fromFile.enabledGroups(FACTOR_TOTP));
    }

    @Test
    public void saveMergeKeepsTheOtherFactorSlice() throws Exception {
        // TOTP write (also carries the shared URLs).
        service.save("digitall", current ->
                current.withFactor(FACTOR_TOTP, true, java.util.Collections.emptyList()).withUrls("/login.html", null));
        // WebAuthn write merges ONLY its slice — must not clobber TOTP or the URL.
        service.save("digitall", current ->
                current.withFactor(FACTOR_WEBAUTHN, true, java.util.Collections.emptyList()));

        MfaSiteConfig config = service.getConfig("digitall");
        assertTrue("TOTP slice preserved", config.isEnabled(FACTOR_TOTP));
        assertTrue("WebAuthn slice added", config.isEnabled(FACTOR_WEBAUTHN));
        assertEquals("URL preserved", "/login.html", config.getLoginUrl());
    }

    @Test
    public void saveAllDefaultDeletesTheFile() throws Exception {
        service.save("digitall", current -> current.withFactor(FACTOR_TOTP, true, null));
        assertTrue(Files.exists(cfgFile("digitall")));

        // Disabling the only factor (and no URLs) leaves an all-default config → file removed.
        service.save("digitall", current -> current.withFactor(FACTOR_TOTP, false, null));
        assertFalse(Files.exists(cfgFile("digitall")));
        assertEquals(MfaSiteConfig.EMPTY, service.getConfig("digitall"));
    }

    @Test
    public void anySiteEnabledScansAllSites() throws Exception {
        assertFalse(service.anySiteEnabled(FACTOR_TOTP));
        service.save("siteA", current -> current.withFactor(FACTOR_TOTP, true, null));
        service.save("siteB", current -> current.withFactor(FACTOR_WEBAUTHN, true, null));
        assertTrue(service.anySiteEnabled(FACTOR_TOTP));
        assertTrue(service.anySiteEnabled(FACTOR_WEBAUTHN));
    }

    // --- siteKey validation (path traversal → arbitrary file write) -------------------------

    @Test
    public void saveRejectsUnsafeSiteKeys() {
        for (String bad : new String[]{"../evil", "a/b", "a\\b", "..", "", " ", "site.cfg", null}) {
            try {
                service.save(bad, current -> current.withFactor(FACTOR_TOTP, true, null));
                fail("Expected rejection of unsafe siteKey: " + bad);
            } catch (IllegalArgumentException expected) {
                // expected
            } catch (Exception e) {
                fail("Expected IllegalArgumentException for siteKey '" + bad + "' but got " + e);
            }
        }
    }

    private static Dictionary<String, Object> loadAsDictionary(Path file) throws Exception {
        Properties properties = new Properties();
        try (InputStream in = Files.newInputStream(file)) {
            properties.load(in);
        }
        Dictionary<String, Object> dict = new Hashtable<>();
        for (String name : properties.stringPropertyNames()) {
            dict.put(name, properties.getProperty(name));
        }
        return dict;
    }
}
