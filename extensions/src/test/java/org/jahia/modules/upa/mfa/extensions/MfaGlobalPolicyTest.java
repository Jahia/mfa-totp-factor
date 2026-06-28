package org.jahia.modules.upa.mfa.extensions;

import org.junit.Test;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import static org.jahia.modules.upa.mfa.extensions.MfaGlobalPolicy.parseEnforcedFactors;
import static org.jahia.modules.upa.mfa.extensions.MfaGlobalPolicy.parseGraceDays;
import static org.jahia.modules.upa.mfa.extensions.MfaGlobalPolicy.parseNotifyEmails;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * The global enforcement policy parsing: the comma-separated {@code enforcedFactors} string is
 * parsed by our code on purpose (an OSGi String[] cannot be expressed reliably in a .cfg — SCR
 * coerces a comma string to ONE bogus element), and {@code graceDays} is clamped so a typo can
 * never disable enforcement forever.
 */
public class MfaGlobalPolicyTest {

    // --- enforcedFactors parsing ---------------------------------------------------------

    @Test
    public void blankOrNullMeansNoEnforcement() {
        assertTrue(parseEnforcedFactors(null).isEmpty());
        assertTrue(parseEnforcedFactors("").isEmpty());
        assertTrue(parseEnforcedFactors("   ").isEmpty());
        assertTrue(parseEnforcedFactors(" , ,").isEmpty());
    }

    @Test
    public void parsesTrimsLowercasesAndDedupes() {
        assertEquals(Arrays.asList("totp", "webauthn"),
                parseEnforcedFactors(" TOTP , webauthn, totp "));
        assertEquals(Arrays.asList("totp"), parseEnforcedFactors("totp"));
    }

    @Test
    public void isEnforcedIsCaseInsensitiveAndNullSafe() {
        MfaGlobalPolicy policy = activated("totp,webauthn", null);
        assertTrue(policy.isEnforced("totp"));
        assertTrue(policy.isEnforced("WebAuthn"));
        assertFalse(policy.isEnforced("email_code"));
        assertFalse(policy.isEnforced(null));
        assertTrue(policy.isEnforcementActive());
    }

    @Test
    public void emptyConfigMeansInactive() {
        MfaGlobalPolicy policy = activated(null, null);
        assertFalse(policy.isEnforcementActive());
        assertFalse(policy.isEnforced("totp"));
        assertEquals(0L, policy.getGraceDays());
    }

    @Test
    public void modifiedConfigReplacesTheFactorList() {
        MfaGlobalPolicy policy = activated("totp", null);
        assertTrue(policy.isEnforced("totp"));
        Map<String, Object> updated = new HashMap<>();
        updated.put("enforcedFactors", "webauthn");
        policy.activate(updated);
        assertFalse(policy.isEnforced("totp"));
        assertTrue(policy.isEnforced("webauthn"));
    }

    // --- graceDays parsing ----------------------------------------------------------------

    @Test
    public void graceDaysDefaultsToZeroOnBlankOrGarbage() {
        assertEquals(0L, parseGraceDays(null));
        assertEquals(0L, parseGraceDays(""));
        assertEquals(0L, parseGraceDays("not-a-number"));
    }

    @Test
    public void graceDaysIsClampedToBounds() {
        assertEquals(0L, parseGraceDays("-5"));
        assertEquals(7L, parseGraceDays(" 7 "));
        assertEquals(MfaGlobalPolicy.MAX_GRACE_DAYS, parseGraceDays("99999"));
    }

    // --- resetRequest.notifyEmail parsing -------------------------------------------------

    @Test
    public void notifyEmailsBlankOrNullMeansNone() {
        assertTrue(parseNotifyEmails(null).isEmpty());
        assertTrue(parseNotifyEmails("").isEmpty());
        assertTrue(parseNotifyEmails("  ").isEmpty());
    }

    @Test
    public void notifyEmailsTrimsDedupesAndRequiresAtSign() {
        assertEquals(Arrays.asList("a@x.com", "b@y.com"),
                parseNotifyEmails(" a@x.com , b@y.com , a@x.com "));
        // entries without a usable '@' are dropped
        assertTrue(parseNotifyEmails("not-an-email, @nodomain, x").isEmpty());
    }

    @Test
    public void notifyEmailsExposedThroughGetter() {
        MfaGlobalPolicy policy = new MfaGlobalPolicy();
        Map<String, Object> props = new HashMap<>();
        props.put("resetRequest.notifyEmail", "security@example.com");
        policy.activate(props);
        assertEquals(Arrays.asList("security@example.com"), policy.getResetNotifyEmails());
    }

    // --- helper ----------------------------------------------------------------------------

    private static MfaGlobalPolicy activated(String enforcedFactors, String graceDays) {
        MfaGlobalPolicy policy = new MfaGlobalPolicy();
        Map<String, Object> props = new HashMap<>();
        if (enforcedFactors != null) {
            props.put("enforcedFactors", enforcedFactors);
        }
        if (graceDays != null) {
            props.put("graceDays", graceDays);
        }
        policy.activate(props);
        return policy;
    }
}
