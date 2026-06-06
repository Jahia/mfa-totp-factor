package org.jahia.modules.upa.mfa.totp;

import org.junit.Before;
import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * RFC 6238 reference vectors for HMAC-SHA1.
 * <p>
 * Seed (ASCII): "12345678901234567890" (20 bytes).
 * <pre>
 *   T (unix sec)       T_counter      SHA-1 8-digit         SHA-1 6-digit
 *      59                  1            94287082             287082
 *      1111111109          37037036     07081804             081804
 *      1111111111          37037037     14050471             050471
 *      1234567890          41152263     89005924             005924
 *      2000000000          66666666     69279037             279037
 * </pre>
 */
public class TotpServiceTest {

    private static final byte[] SEED_SHA1 = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);

    private TotpService service;

    @Before
    public void setUp() {
        service = new TotpService();
    }

    @Test
    public void generateCode_referenceVector_T59() {
        long counter = 59L / TotpService.TIME_STEP_SECONDS; // = 1
        assertEquals("287082", service.generateCode(SEED_SHA1, counter));
    }

    @Test
    public void generateCode_referenceVector_1111111109() {
        long counter = 1111111109L / TotpService.TIME_STEP_SECONDS;
        assertEquals("081804", service.generateCode(SEED_SHA1, counter));
    }

    @Test
    public void generateCode_referenceVector_1111111111() {
        long counter = 1111111111L / TotpService.TIME_STEP_SECONDS;
        assertEquals("050471", service.generateCode(SEED_SHA1, counter));
    }

    @Test
    public void generateCode_referenceVector_1234567890() {
        long counter = 1234567890L / TotpService.TIME_STEP_SECONDS;
        assertEquals("005924", service.generateCode(SEED_SHA1, counter));
    }

    @Test
    public void generateCode_referenceVector_2000000000() {
        long counter = 2000000000L / TotpService.TIME_STEP_SECONDS;
        assertEquals("279037", service.generateCode(SEED_SHA1, counter));
    }

    @Test
    public void generateCode_isAlwaysSixDigits() {
        // try a counter known to yield a small numeric value once truncated
        for (long c = 0; c < 10000; c++) {
            String code = service.generateCode(SEED_SHA1, c);
            assertEquals("generated codes must be 6 chars (counter=" + c + ")",
                    TotpService.DIGITS, code.length());
        }
    }

    @Test
    public void verifyCode_withinWindow_succeedsAndReturnsCounter() {
        long counter = 1111111111L / TotpService.TIME_STEP_SECONDS;
        long now = counter * TotpService.TIME_STEP_SECONDS;
        Optional<Long> matched = service.verifyCode(SEED_SHA1, "050471", now, -1L, 1);
        assertTrue(matched.isPresent());
        assertEquals(Long.valueOf(counter), matched.get());
    }

    @Test
    public void verifyCode_replayWithinWindow_isRejectedByCounter() {
        long counter = 1111111111L / TotpService.TIME_STEP_SECONDS;
        long now = counter * TotpService.TIME_STEP_SECONDS;
        // already used this counter -> must reject
        Optional<Long> matched = service.verifyCode(SEED_SHA1, "050471", now, counter, 1);
        assertFalse(matched.isPresent());
    }

    @Test
    public void verifyCode_priorWindowAccepted_withDrift1() {
        long current = 1111111111L / TotpService.TIME_STEP_SECONDS;
        long now = current * TotpService.TIME_STEP_SECONDS;
        // code is for counter `current - 1` -> must succeed with drift = 1
        String priorCode = service.generateCode(SEED_SHA1, current - 1);
        Optional<Long> matched = service.verifyCode(SEED_SHA1, priorCode, now, -1L, 1);
        assertTrue(matched.isPresent());
        assertEquals(Long.valueOf(current - 1), matched.get());
    }

    @Test
    public void verifyCode_outOfWindow_isRejected() {
        long current = 1111111111L / TotpService.TIME_STEP_SECONDS;
        long now = current * TotpService.TIME_STEP_SECONDS;
        // code from T-2 must be rejected
        String farPast = service.generateCode(SEED_SHA1, current - 2);
        Optional<Long> matched = service.verifyCode(SEED_SHA1, farPast, now, -1L, 1);
        assertFalse(matched.isPresent());
    }

    @Test
    public void verifyCode_wrongCode_isRejected() {
        long now = 1111111111L;
        Optional<Long> matched = service.verifyCode(SEED_SHA1, "000000", now, -1L, 1);
        assertFalse(matched.isPresent());
    }

    @Test
    public void verifyCode_malformedInput_isRejected() {
        long now = 1111111111L;
        assertFalse(service.verifyCode(SEED_SHA1, null, now, -1L, 1).isPresent());
        assertFalse(service.verifyCode(SEED_SHA1, "abc", now, -1L, 1).isPresent());
        assertFalse(service.verifyCode(SEED_SHA1, "1234567", now, -1L, 1).isPresent());
    }

    @Test
    public void base32_roundTrip() {
        byte[] generated = service.generateSecret();
        String b32 = service.toBase32(generated);
        byte[] decoded = service.fromBase32(b32);
        assertEquals(TotpService.SECRET_BYTES, decoded.length);
        // round-trip equality
        for (int i = 0; i < generated.length; i++) {
            assertEquals(generated[i], decoded[i]);
        }
    }

    @Test
    public void looksLikeBackupCode_detectsTotpVsBackup() {
        assertFalse(TotpService.looksLikeBackupCode("123456"));
        assertTrue(TotpService.looksLikeBackupCode("ABCDE12345"));
        assertTrue(TotpService.looksLikeBackupCode("12345"));
        assertTrue(TotpService.looksLikeBackupCode("1234567"));
    }

    @Test
    public void buildOtpauthUri_containsExpectedParams() {
        String uri = service.buildOtpauthUri("Jahia", "alice@example.com", "JBSWY3DPEHPK3PXP");
        assertNotNull(uri);
        assertTrue(uri.startsWith("otpauth://totp/"));
        assertTrue(uri.contains("secret=JBSWY3DPEHPK3PXP"));
        assertTrue(uri.contains("issuer=Jahia"));
        assertTrue(uri.contains("algorithm=SHA1"));
        assertTrue(uri.contains("digits=6"));
        assertTrue(uri.contains("period=30"));
    }
}
