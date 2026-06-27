package org.jahia.modules.upa.mfa.extensions;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Dictionary;
import java.util.Hashtable;
import java.util.Properties;
import java.util.concurrent.CyclicBarrier;

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

    // --- Concurrency: writeLock serializes two simultaneous save() calls ---------------------

    @Test
    public void concurrentSavesOnTwoFactorsBothSurviveAndHitTheFile() throws Exception {
        for (int i = 0; i < 50; i++) {
            final MfaSiteConfigService svc = new MfaSiteConfigService();
            final CyclicBarrier barrier = new CyclicBarrier(2);
            final AtomicReferenceThrowable failure = new AtomicReferenceThrowable();

            Runnable enableTotp = () -> awaitThen(barrier, failure, () ->
                    svc.save("digitall", c -> c.withFactor(FACTOR_TOTP, true, null)));
            Runnable enableWebauthn = () -> awaitThen(barrier, failure, () ->
                    svc.save("digitall", c -> c.withFactor(FACTOR_WEBAUTHN, true, null)));

            Thread t1 = new Thread(enableTotp);
            Thread t2 = new Thread(enableWebauthn);
            t1.start();
            t2.start();
            t1.join();
            t2.join();
            if (failure.error != null) {
                fail("save() threw under concurrency: " + failure.error);
            }

            MfaSiteConfig config = svc.getConfig("digitall");
            assertTrue("iteration " + i + ": TOTP enabled", config.isEnabled(FACTOR_TOTP));
            assertTrue("iteration " + i + ": WebAuthn enabled", config.isEnabled(FACTOR_WEBAUTHN));

            String fileContent = new String(Files.readAllBytes(cfgFile("digitall")), StandardCharsets.UTF_8);
            assertTrue("iteration " + i + ": .cfg has totp.enabled=true",
                    fileContent.contains("totp.enabled=true"));
            assertTrue("iteration " + i + ": .cfg has webauthn.enabled=true",
                    fileContent.contains("webauthn.enabled=true"));
        }
    }

    @Test
    public void concurrentReadModifyWriteOnOverlappingStateLosesNoUpdate() throws Exception {
        // Both threads read-modify-write the SAME site, touching overlapping state: thread A flips
        // totp.enabled, thread B sets loginUrl. Each save() is a read-modify-write on the shared
        // snapshot, so WITHOUT the writeLock one thread's read-then-write could clobber the other's
        // committed change (a classic lost update). The lock serializes them, so the final config
        // must carry BOTH totp.enabled=true AND loginUrl=/login.html.
        for (int i = 0; i < 50; i++) {
            final MfaSiteConfigService svc = new MfaSiteConfigService();
            final CyclicBarrier barrier = new CyclicBarrier(2);
            final AtomicReferenceThrowable failure = new AtomicReferenceThrowable();

            Runnable enableTotp = () -> awaitThen(barrier, failure, () ->
                    svc.save("digitall", c -> c.withFactor(FACTOR_TOTP, true, null)));
            Runnable setLoginUrl = () -> awaitThen(barrier, failure, () ->
                    svc.save("digitall", c -> c.withUrls("/login.html", null)));

            Thread t1 = new Thread(enableTotp);
            Thread t2 = new Thread(setLoginUrl);
            t1.start();
            t2.start();
            t1.join();
            t2.join();
            if (failure.error != null) {
                fail("save() threw under concurrency: " + failure.error);
            }

            MfaSiteConfig config = svc.getConfig("digitall");
            assertTrue("iteration " + i + ": TOTP enabled (no lost update)", config.isEnabled(FACTOR_TOTP));
            assertEquals("iteration " + i + ": loginUrl preserved (no lost update)",
                    "/login.html", config.getLoginUrl());
        }
    }

    @Test
    public void updatedSerializesWithSaveUnderTheWriteLock() throws Exception {
        // save()'s read-modify-write and updated()'s replace both take the writeLock, so a
        // concurrent updated() can never interleave INSIDE save()'s critical section and produce a
        // torn snapshot. We make save()'s merge lambda park on a barrier (it is invoked while save()
        // already holds the lock), release a concurrent updated() for the SAME site, and assert the
        // final map is one fully-consistent whole snapshot - one writer's commit, never a mix.
        final MfaSiteConfigService svc = new MfaSiteConfigService();
        final CyclicBarrier insideLock = new CyclicBarrier(2);
        final AtomicReferenceThrowable failure = new AtomicReferenceThrowable();

        // Thread A: save() that enables totp; its merge lambda parks on the barrier WHILE holding the
        // writeLock, guaranteeing updated() (below) cannot enter its own synchronized block yet.
        Thread saver = new Thread(() -> {
            try {
                svc.save("digitall", c -> {
                    awaitQuietly(insideLock);
                    return c.withFactor(FACTOR_TOTP, true, null);
                });
            } catch (Exception e) {
                failure.set(e);
            }
        });

        // Thread B: an updated() carrying a DIFFERENT, totp-less snapshot (loginUrl only). If it
        // could interleave inside save()'s critical section, the result would be torn.
        Thread updater = new Thread(() -> {
            awaitQuietly(insideLock); // let save() get into its locked merge first
            svc.updated("pid-x", props("siteKey", "digitall", "loginUrl", "/login.html"));
        });

        saver.start();
        updater.start();
        saver.join();
        updater.join();
        if (failure.error != null) {
            fail("save()/updated() threw under concurrency: " + failure.error);
        }

        // Whichever writer committed last wins as a WHOLE snapshot: either the save result (totp
        // enabled with no URL) or the updated result (totp disabled with the login URL set), never
        // a torn half-merge combining both and never an empty config. Both ran under the same lock.
        MfaSiteConfig config = svc.getConfig("digitall");
        boolean saveWonWhole = config.isEnabled(FACTOR_TOTP) && config.getLoginUrl() == null;
        boolean updateWonWhole = !config.isEnabled(FACTOR_TOTP) && "/login.html".equals(config.getLoginUrl());
        assertTrue("the map must reflect exactly one writer's whole snapshot, not a torn merge",
                saveWonWhole || updateWonWhole);
    }

    // --- karaf.base fallback when karaf.etc is unset -----------------------------------------

    @Test
    public void writesUnderKarafBaseEtcWhenKarafEtcIsUnset() throws Exception {
        System.clearProperty("karaf.etc");
        Path etcUnderBase = Files.createDirectory(etc.getRoot().toPath().resolve("etc"));
        System.setProperty("karaf.base", etc.getRoot().getAbsolutePath());
        try {
            MfaSiteConfigService svc = new MfaSiteConfigService();
            svc.save("digitall", c -> c.withFactor(FACTOR_TOTP, true, null));
            assertTrue("the .cfg must land under <karaf.base>/etc",
                    Files.exists(etcUnderBase.resolve(MfaSiteConfigService.FACTORY_PID + "-digitall.cfg")));
        } finally {
            System.clearProperty("karaf.base");
        }
    }

    // --- isAllDefault: a URL-only config (no factors) is RETAINED ----------------------------

    @Test
    public void urlOnlyConfigIsRetainedAndClearingTheUrlDeletesIt() throws Exception {
        // Only a loginUrl, every factor disabled → still meaningful → file retained.
        service.save("digitall", current -> current.withUrls("/login.html", null));
        assertTrue(Files.exists(cfgFile("digitall")));
        assertEquals("/login.html", service.getConfig("digitall").getLoginUrl());

        // Clearing the URL leaves an all-default config → file deleted.
        service.save("digitall", current -> current.withUrls(null, null));
        assertFalse(Files.exists(cfgFile("digitall")));
        assertEquals(MfaSiteConfig.EMPTY, service.getConfig("digitall"));
    }

    // --- etcDir cache: the resolved directory is reused across writes ------------------------

    @Test
    public void etcDirIsCachedAfterTheFirstWrite() throws Exception {
        service.save("siteA", current -> current.withFactor(FACTOR_TOTP, true, null));
        assertTrue(Files.exists(cfgFile("siteA")));

        // Clear the system property: a non-cached resolve would now fail. The cached dir is reused.
        System.clearProperty("karaf.etc");
        service.save("siteB", current -> current.withFactor(FACTOR_TOTP, true, null));
        assertTrue("second write must reuse the cached etc dir", Files.exists(cfgFile("siteB")));
    }

    // --- PID-rename: the stale siteKey entry is evicted --------------------------------------

    @Test
    public void pidRenameEvictsTheStaleSiteEntry() {
        service.updated("pid1", props("siteKey", "siteA", "totp.enabled", "true"));
        assertTrue(service.getConfig("siteA").isEnabled(FACTOR_TOTP));

        // Same pid now points at a different site: the old entry must be removed.
        service.updated("pid1", props("siteKey", "siteB", "totp.enabled", "true"));
        assertEquals(MfaSiteConfig.EMPTY, service.getConfig("siteA"));
        assertTrue(service.getConfig("siteB").isEnabled(FACTOR_TOTP));
    }

    // --- Group-name validation (config-injection chokepoint) ---------------------------------

    @Test
    public void groupNameWithNewlineOrCommaIsRejected() {
        for (String bad : new String[]{"editors\nloginUrl=/evil", "a,b", "a=b", "with space", "a#b"}) {
            try {
                service.save("digitall", current ->
                        current.withFactor(FACTOR_TOTP, true, java.util.Collections.singletonList(bad)));
                fail("Expected rejection of unsafe group name: '" + bad + "'");
            } catch (IllegalArgumentException expected) {
                // expected
            } catch (Exception e) {
                fail("Expected IllegalArgumentException for group '" + bad + "' but got " + e);
            }
        }
    }

    // --- Readiness: eager activate() scan loads a pre-existing .cfg ---------------------------

    @Test
    public void activateEagerlyLoadsPreexistingCfgAndIsReady() throws Exception {
        // A .cfg already sitting in the etc dir before the component activates.
        Path file = cfgFile("preexisting");
        Files.write(file, ("siteKey=preexisting\n"
                + "loginUrl=/login.html\n"
                + "totp.enabled=true\n"
                + "totp.enabledGroups=editors\n").getBytes(StandardCharsets.UTF_8));

        MfaSiteConfigService svc = new MfaSiteConfigService();
        assertFalse("not ready before activate", svc.isReady());
        svc.activate();

        assertTrue("ready after the eager scan", svc.isReady());
        MfaSiteConfig config = svc.getConfig("preexisting");
        assertTrue(config.isEnabled(FACTOR_TOTP));
        assertEquals("/login.html", config.getLoginUrl());
        assertEquals(java.util.Collections.singletonList("editors"), config.enabledGroups(FACTOR_TOTP));
    }

    /** Run an action after both threads reach the barrier; record the first throwable. */
    private static void awaitThen(CyclicBarrier barrier, AtomicReferenceThrowable failure, ThrowingRunnable action) {
        try {
            barrier.await();
            action.run();
        } catch (Exception e) {
            failure.set(e);
        }
    }

    /** Await a barrier, turning the checked exceptions into an unchecked one (test-only). */
    private static void awaitQuietly(CyclicBarrier barrier) {
        try {
            barrier.await();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @FunctionalInterface
    private interface ThrowingRunnable {
        void run() throws Exception;
    }

    /** Tiny holder so the worker threads can report a failure back to the test thread. */
    private static final class AtomicReferenceThrowable {
        private volatile Throwable error;

        private synchronized void set(Throwable t) {
            if (error == null) {
                error = t;
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
