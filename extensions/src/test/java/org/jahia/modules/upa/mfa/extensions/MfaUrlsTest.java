package org.jahia.modules.upa.mfa.extensions;

import org.junit.Test;

import static org.jahia.modules.upa.mfa.extensions.MfaUrls.isSafeSiteRelativeUrl;
import static org.jahia.modules.upa.mfa.extensions.MfaUrls.validateSiteRelativeUrl;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * Open-redirect guard for the per-site / global login/logout URLs: only server-relative paths may
 * ever be stored or served. A site admin must NOT be able to point a site's login redirect at an
 * external host ({@code https://attacker.example}, {@code //attacker.example}, the
 * {@code /\attacker.example} browser backslash quirk) or at a {@code javascript:} URL.
 */
public class MfaUrlsTest {

    // --- isSafeSiteRelativeUrl: the no-throw predicate used on the read path ---

    @Test
    public void acceptsPlainSiteRelativePaths() {
        assertTrue(isSafeSiteRelativeUrl("/sites/mySite/login.html"));
        assertTrue(isSafeSiteRelativeUrl("/cms/login"));
        assertTrue(isSafeSiteRelativeUrl("/"));
        assertTrue(isSafeSiteRelativeUrl("/login?site=a&lang=en"));
    }

    @Test
    public void rejectsAbsoluteAndSchemeUrls() {
        assertFalse(isSafeSiteRelativeUrl("https://attacker.example/phish"));
        assertFalse(isSafeSiteRelativeUrl("http://attacker.example"));
        assertFalse(isSafeSiteRelativeUrl("javascript:alert(1)"));
        assertFalse(isSafeSiteRelativeUrl("data:text/html,x"));
    }

    @Test
    public void rejectsProtocolRelativeUrls() {
        assertFalse("//host is protocol-relative", isSafeSiteRelativeUrl("//attacker.example"));
        assertFalse("browsers treat /\\host like //host", isSafeSiteRelativeUrl("/\\attacker.example"));
    }

    @Test
    public void rejectsControlCharactersWhitespaceAndBackslashes() {
        assertFalse(isSafeSiteRelativeUrl("/login page.html"));
        assertFalse(isSafeSiteRelativeUrl("/login\tpage"));
        assertFalse(isSafeSiteRelativeUrl("/login\r\nSet-Cookie: x"));
        assertFalse(isSafeSiteRelativeUrl("/path\\segment"));
        assertFalse(isSafeSiteRelativeUrl("/path\u0000x"));
    }

    @Test
    public void rejectsBlankAndRelativeWithoutLeadingSlash() {
        assertFalse(isSafeSiteRelativeUrl(null));
        assertFalse(isSafeSiteRelativeUrl(""));
        assertFalse(isSafeSiteRelativeUrl("sites/mySite/login.html"));
    }

    // --- validateSiteRelativeUrl: the throwing normalizer used on the write path ---

    @Test
    public void validateReturnsNullForBlankInput() {
        assertNull(validateSiteRelativeUrl(null));
        assertNull(validateSiteRelativeUrl(""));
        assertNull(validateSiteRelativeUrl("   "));
    }

    @Test
    public void validateTrimsSurroundingWhitespace() {
        assertEquals("/sites/mySite/login.html", validateSiteRelativeUrl("  /sites/mySite/login.html  "));
    }

    @Test(expected = IllegalArgumentException.class)
    public void validateThrowsOnAbsoluteUrl() {
        validateSiteRelativeUrl("https://attacker.example/phish");
    }

    @Test(expected = IllegalArgumentException.class)
    public void validateThrowsOnProtocolRelativeUrl() {
        validateSiteRelativeUrl("//attacker.example");
    }

    @Test(expected = IllegalArgumentException.class)
    public void validateThrowsOnJavascriptUrl() {
        validateSiteRelativeUrl("javascript:alert(1)");
    }
}
