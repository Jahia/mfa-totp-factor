package org.jahia.modules.upa.mfa.extensions.gql;

import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.Dictionary;
import java.util.Hashtable;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

/**
 * Validation/serialization rules for the administration UI's configuration mutation: unknown
 * factor names are refused (a typo would create an unsatisfiable policy and lock users out),
 * grace bounds apply, whitelist entries must be syntactically valid, and unknown keys (e.g.
 * felix.fileinstall.filename) are preserved.
 */
public class MfaExtensionsConfigSupportTest {

    private static final List<String> REGISTERED = Arrays.asList("totp", "webauthn");

    private static MfaExtensionsConfigSupport.Update update(List<String> factors, Integer grace, Boolean gate,
                                                            String whitelist, String loginUrl, String logoutUrl) {
        return new MfaExtensionsConfigSupport.Update(factors, grace, gate, whitelist, loginUrl, logoutUrl, null, null);
    }

    private static MfaExtensionsConfigSupport.Update emailUpdate(String resetNotifyEmail) {
        return new MfaExtensionsConfigSupport.Update(null, null, null, null, null, null, resetNotifyEmail, null);
    }

    private static MfaExtensionsConfigSupport.Update trustForwardedForUpdate(Boolean trust) {
        return new MfaExtensionsConfigSupport.Update(null, null, null, null, null, null, null, trust);
    }

    @Test
    public void appliesAllKeysAndPreservesUnknownOnes() {
        Dictionary<String, Object> props = new Hashtable<>();
        props.put("felix.fileinstall.filename", "file:/karaf/etc/org.jahia.modules.mfa.extensions.cfg");

        MfaExtensionsConfigSupport.applyUpdate(props,
                update(Arrays.asList("TOTP", "webauthn", "totp"), 7, true,
                        "203.0.113.7, 10.0.0.0/8", "/sites/a/login.html", ""),
                REGISTERED);

        assertEquals("totp,webauthn", props.get("enforcedFactors"));
        assertEquals("7", props.get("graceDays"));
        assertEquals("true", props.get("loginGate.enabled"));
        assertEquals("203.0.113.7, 10.0.0.0/8", props.get("loginGate.ipWhitelist"));
        assertEquals("/sites/a/login.html", props.get("loginUrl"));
        assertEquals("", props.get("logoutUrl"));
        assertEquals("unknown keys must be preserved",
                "file:/karaf/etc/org.jahia.modules.mfa.extensions.cfg", props.get("felix.fileinstall.filename"));
    }

    @Test
    public void nullArgumentsLeaveKeysUntouched() {
        Dictionary<String, Object> props = new Hashtable<>();
        props.put("enforcedFactors", "totp");
        props.put("graceDays", "3");

        MfaExtensionsConfigSupport.applyUpdate(props,
                update(null, null, null, null, null, null), REGISTERED);

        assertEquals("totp", props.get("enforcedFactors"));
        assertEquals("3", props.get("graceDays"));
    }

    @Test
    public void rejectsUnknownFactor() {
        Dictionary<String, Object> props = new Hashtable<>();
        MfaExtensionsConfigSupport.Update bad =
                update(Collections.singletonList("totq"), null, null, null, null, null);
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> MfaExtensionsConfigSupport.applyUpdate(props, bad, REGISTERED));
        assertEquals(MfaExtensionsConfigSupport.ERROR_UNKNOWN_FACTOR, e.getMessage());
    }

    @Test
    public void rejectsOutOfRangeGraceDays() {
        for (int badValue : new int[]{-1, 366, 99999}) {
            Dictionary<String, Object> props = new Hashtable<>();
            MfaExtensionsConfigSupport.Update bad = update(null, badValue, null, null, null, null);
            IllegalArgumentException e = assertThrows("graceDays " + badValue, IllegalArgumentException.class,
                    () -> MfaExtensionsConfigSupport.applyUpdate(props, bad, REGISTERED));
            assertEquals(MfaExtensionsConfigSupport.ERROR_INVALID_GRACE_DAYS, e.getMessage());
        }
    }

    @Test
    public void rejectsInvalidWhitelistEntries() {
        Dictionary<String, Object> props = new Hashtable<>();
        MfaExtensionsConfigSupport.Update bad =
                update(null, null, null, "10.0.0.0/8, not-an-ip", null, null);
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> MfaExtensionsConfigSupport.applyUpdate(props, bad, REGISTERED));
        assertEquals(MfaExtensionsConfigSupport.ERROR_INVALID_WHITELIST, e.getMessage());
    }

    @Test
    public void trustForwardedForDefaultsTrueAndPersists() {
        // Absent key reads as true (matches the gate's backward-compatible default).
        assertTrue(MfaExtensionsConfigSupport.read(new Hashtable<>(), REGISTERED).isLoginGateTrustForwardedFor());

        Dictionary<String, Object> props = new Hashtable<>();
        MfaExtensionsConfigSupport.applyUpdate(props, trustForwardedForUpdate(false), REGISTERED);
        assertEquals("false", props.get("loginGate.trustForwardedFor"));
        assertFalse(MfaExtensionsConfigSupport.read(props, REGISTERED).isLoginGateTrustForwardedFor());
    }

    @Test
    public void acceptsAndDedupesValidNotifyEmails() {
        Dictionary<String, Object> props = new Hashtable<>();
        MfaExtensionsConfigSupport.applyUpdate(props,
                emailUpdate(" a@x.com , b@y.com , a@x.com "), REGISTERED);
        assertEquals("a@x.com,b@y.com", props.get("resetRequest.notifyEmail"));
    }

    @Test
    public void rejectsMalformedNotifyEmail() {
        Dictionary<String, Object> props = new Hashtable<>();
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> MfaExtensionsConfigSupport.applyUpdate(props, emailUpdate("a@x.com, not-an-email"), REGISTERED));
        assertEquals(MfaExtensionsConfigSupport.ERROR_INVALID_EMAIL, e.getMessage());
    }

    @Test
    public void blankNotifyEmailClearsTheKey() {
        Dictionary<String, Object> props = new Hashtable<>();
        props.put("resetRequest.notifyEmail", "old@x.com");
        MfaExtensionsConfigSupport.applyUpdate(props, emailUpdate("  "), REGISTERED);
        assertEquals("", props.get("resetRequest.notifyEmail"));
    }

    @Test
    public void emptyValuesClearKeys() {
        Dictionary<String, Object> props = new Hashtable<>();
        props.put("enforcedFactors", "totp");
        props.put("loginGate.ipWhitelist", "10.0.0.0/8");

        MfaExtensionsConfigSupport.applyUpdate(props,
                update(Collections.emptyList(), 0, false, "", "", ""), REGISTERED);

        assertEquals("", props.get("enforcedFactors"));
        assertEquals("", props.get("loginGate.ipWhitelist"));
        assertEquals("0", props.get("graceDays"));
        assertEquals("false", props.get("loginGate.enabled"));
    }

    @Test
    public void acceptsSafeServerRelativeAndHttpAbsoluteGlobalUrls() {
        Dictionary<String, Object> props = new Hashtable<>();
        MfaExtensionsConfigSupport.applyUpdate(props,
                update(null, null, null, null, "/sites/a/login.html", "https://sso.example.com/logout"),
                REGISTERED);
        assertEquals("/sites/a/login.html", props.get("loginUrl"));
        assertEquals("https://sso.example.com/logout", props.get("logoutUrl"));
    }

    @Test
    public void rejectsDangerousSchemeGlobalUrls() {
        for (String bad : new String[]{"javascript:alert(1)", "DATA:text/html;base64,x",
                " vbscript:msgbox", "//evil.example", "ftp://x", "not a url"}) {
            Dictionary<String, Object> props = new Hashtable<>();
            MfaExtensionsConfigSupport.Update u = update(null, null, null, null, bad, null);
            IllegalArgumentException e = assertThrows("loginUrl '" + bad + "'", IllegalArgumentException.class,
                    () -> MfaExtensionsConfigSupport.applyUpdate(props, u, REGISTERED));
            assertEquals(MfaExtensionsConfigSupport.ERROR_INVALID_URL, e.getMessage());
        }
    }

    @Test
    public void blankGlobalUrlClearsTheKey() {
        Dictionary<String, Object> props = new Hashtable<>();
        props.put("loginUrl", "/old");
        MfaExtensionsConfigSupport.applyUpdate(props,
                update(null, null, null, null, "  ", null), REGISTERED);
        assertEquals("", props.get("loginUrl"));
    }

    @Test
    public void readsDefaultsWhenPropertiesAbsent() {
        MfaExtensionsConfiguration cfg = MfaExtensionsConfigSupport.read(null, REGISTERED);
        assertTrue(cfg.getEnforcedFactors().isEmpty());
        assertEquals(0L, cfg.getGraceDays());
        assertFalse(cfg.isLoginGateEnabled());
        assertEquals("", cfg.getLoginGateIpWhitelist());
        assertEquals(REGISTERED, cfg.getRegisteredFactors());
    }

    @Test
    public void readsPopulatedProperties() {
        Dictionary<String, Object> props = new Hashtable<>();
        props.put("enforcedFactors", "totp, WEBAUTHN");
        props.put("graceDays", "9");
        props.put("loginGate.enabled", "true");
        props.put("loginGate.ipWhitelist", "10.0.0.0/8");
        props.put("loginUrl", "/sites/a/login.html");

        MfaExtensionsConfiguration cfg = MfaExtensionsConfigSupport.read(props, REGISTERED);
        assertEquals(Arrays.asList("totp", "webauthn"), cfg.getEnforcedFactors());
        assertEquals(9L, cfg.getGraceDays());
        assertTrue(cfg.isLoginGateEnabled());
        assertEquals("10.0.0.0/8", cfg.getLoginGateIpWhitelist());
        assertEquals("/sites/a/login.html", cfg.getLoginUrl());
    }
}
