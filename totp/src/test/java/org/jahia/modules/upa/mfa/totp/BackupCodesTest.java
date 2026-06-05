package org.jahia.modules.upa.mfa.totp;

import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

/**
 * Tests for {@link BackupCodes} focused on the security-review fixes:
 * <ul>
 *     <li>up-front length cap on submitted code (no PBKDF2 amplification);</li>
 *     <li>refusal of stored hashes with sub-minimum PBKDF2 iteration counts (tamper / downgrade
 *         defense).</li>
 * </ul>
 */
public class BackupCodesTest {

    private BackupCodes backupCodes;

    @Before
    public void setUp() {
        backupCodes = new BackupCodes();
    }

    @Test
    public void generate_returnsConfiguredCountAndLength() {
        List<String> codes = backupCodes.generate();
        assertEquals(BackupCodes.CODE_COUNT, codes.size());
        for (String c : codes) {
            assertEquals(BackupCodes.CODE_LENGTH, c.length());
        }
    }

    @Test
    public void verifyAndIndex_matchesStoredHash() {
        List<String> plaintext = backupCodes.generate();
        String hash = backupCodes.hash(plaintext.get(0));
        Optional<Integer> idx = backupCodes.verifyAndIndex(Collections.singletonList(hash), plaintext.get(0));
        assertTrue(idx.isPresent());
        assertEquals(Integer.valueOf(0), idx.get());
    }

    @Test
    public void verifyAndIndex_rejectsHashWithWeakIterations() {
        // Forge a hash with iterations = 1 (well below the enforced minimum).
        byte[] salt = new byte[16];
        Arrays.fill(salt, (byte) 0x42);
        byte[] fakeKey = new byte[32];
        Arrays.fill(fakeKey, (byte) 0xAA);
        String enc = "pbkdf2-sha256$1$"
                + Base64.getEncoder().withoutPadding().encodeToString(salt) + "$"
                + Base64.getEncoder().withoutPadding().encodeToString(fakeKey);
        Optional<Integer> idx = backupCodes.verifyAndIndex(Collections.singletonList(enc), "ANYTHING");
        assertFalse(idx.isPresent());
    }

    @Test
    public void verifyAndIndex_rejectsSubmittedCodeLongerThanMaxCodeLength() {
        // Hash a valid code, then submit a multi-KB code: must be rejected up front (no PBKDF2 work).
        List<String> plaintext = backupCodes.generate();
        String hash = backupCodes.hash(plaintext.get(0));

        StringBuilder huge = new StringBuilder(TotpService.MAX_CODE_LENGTH + 1024);
        for (int i = 0; i < TotpService.MAX_CODE_LENGTH + 1024; i++) {
            huge.append('A');
        }
        Optional<Integer> idx = backupCodes.verifyAndIndex(Collections.singletonList(hash), huge.toString());
        assertFalse(idx.isPresent());
    }

    @Test
    public void looksLikeBackupCode_detectsTotpVsBackup() {
        assertFalse(BackupCodes.looksLikeBackupCode("123456"));
        assertTrue(BackupCodes.looksLikeBackupCode("ABCDE12345"));
        assertTrue(BackupCodes.looksLikeBackupCode("12345"));
        assertTrue(BackupCodes.looksLikeBackupCode("1234567"));
    }
}
