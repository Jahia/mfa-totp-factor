package org.jahia.modules.upa.mfa.totp;

import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.jahia.modules.upa.mfa.totp.TotpLoginGateFilter.isIpLiteral;
import static org.jahia.modules.upa.mfa.totp.TotpLoginGateFilter.isWhitelisted;
import static org.jahia.modules.upa.mfa.totp.TotpLoginGateFilter.parseWhitelist;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * The /cms/login gate's whitelist matching: the client IP (first X-Forwarded-For entry) must
 * match a configured address or CIDR block. The matcher must never DNS-resolve the
 * attacker-controlled header value, and mixed IPv4/IPv6 comparisons must never match.
 */
public class TotpLoginGateFilterTest {

    // --- Whitelist parsing -------------------------------------------------------------

    @Test
    public void parsesCommaSeparatedEntriesAndTrims() {
        List<String> entries = parseWhitelist("203.0.113.7 , 10.0.0.0/8,2001:db8::/32");
        assertEquals(Arrays.asList("203.0.113.7", "10.0.0.0/8", "2001:db8::/32"), entries);
    }

    @Test
    public void blankOrNullWhitelistIsEmpty() {
        assertTrue(parseWhitelist(null).isEmpty());
        assertTrue(parseWhitelist("").isEmpty());
        assertTrue(parseWhitelist("  ,  ,").isEmpty());
    }

    @Test
    public void invalidEntriesAreDropped() {
        // hostnames, garbage, out-of-range prefixes must be ignored (and logged), not crash
        List<String> entries = parseWhitelist("evil.example.com, 10.0.0.0/99, not-an-ip, 192.168.1.1");
        assertEquals(Collections.singletonList("192.168.1.1"), entries);
    }

    // --- Exact address matching --------------------------------------------------------

    @Test
    public void exactIpv4Match() {
        List<String> wl = parseWhitelist("203.0.113.7");
        assertTrue(isWhitelisted("203.0.113.7", wl));
        assertFalse(isWhitelisted("203.0.113.8", wl));
    }

    @Test
    public void exactIpv6MatchIsFormInsensitive() {
        List<String> wl = parseWhitelist("2001:db8::1");
        assertTrue("compressed and expanded forms are the same address",
                isWhitelisted("2001:0db8:0000:0000:0000:0000:0000:0001", wl));
        assertFalse(isWhitelisted("2001:db8::2", wl));
    }

    // --- CIDR matching ------------------------------------------------------------------

    @Test
    public void ipv4CidrBoundaries() {
        List<String> wl = parseWhitelist("10.1.2.0/24");
        assertTrue(isWhitelisted("10.1.2.0", wl));
        assertTrue(isWhitelisted("10.1.2.255", wl));
        assertFalse(isWhitelisted("10.1.3.0", wl));
        assertFalse(isWhitelisted("10.1.1.255", wl));
    }

    @Test
    public void ipv4CidrNonOctetAlignedPrefix() {
        List<String> wl = parseWhitelist("192.168.0.0/22"); // covers 192.168.0.0 - 192.168.3.255
        assertTrue(isWhitelisted("192.168.3.255", wl));
        assertFalse(isWhitelisted("192.168.4.0", wl));
    }

    @Test
    public void ipv6CidrPrefix() {
        List<String> wl = parseWhitelist("2001:db8::/32");
        assertTrue(isWhitelisted("2001:db8:ffff::1", wl));
        assertFalse(isWhitelisted("2001:db9::1", wl));
    }

    @Test
    public void mixedFamiliesNeverMatch() {
        assertFalse("a v4 client must not match a v6 block",
                isWhitelisted("10.0.0.1", parseWhitelist("2001:db8::/32")));
        assertFalse("a v6 client must not match a v4 block",
                isWhitelisted("2001:db8::1", parseWhitelist("10.0.0.0/8")));
    }

    // --- Hostility of the client value ---------------------------------------------------

    @Test
    public void hostnamesAndGarbageNeverMatchAndAreNeverResolved() {
        List<String> wl = parseWhitelist("10.0.0.0/8");
        assertFalse(isWhitelisted("evil.example.com", wl));
        assertFalse(isWhitelisted("localhost", wl));
        assertFalse(isWhitelisted("", wl));
        assertFalse(isWhitelisted(null, wl));
        assertFalse(isWhitelisted("10.0.0.1; DROP TABLE", wl));
    }

    @Test
    public void emptyWhitelistMatchesNothing() {
        assertFalse(isWhitelisted("127.0.0.1", Collections.emptyList()));
    }

    @Test
    public void ipLiteralDetection() {
        assertTrue(isIpLiteral("192.168.1.1"));
        assertTrue(isIpLiteral("::1"));
        assertTrue(isIpLiteral("::ffff:192.0.2.1")); // v4-mapped v6
        assertFalse("hex-only hostnames must not be treated as IPs", isIpLiteral("abcdef"));
        assertFalse("out-of-range octets must not fall through to DNS", isIpLiteral("192.168.1.256"));
        assertFalse(isIpLiteral("example.com"));
        assertFalse(isIpLiteral(null));
        assertFalse(isIpLiteral(""));
    }
}
