package org.jahia.modules.upa.mfa.extensions;

import org.osgi.service.component.annotations.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

/**
 * Backup code generation and verification — shared across MFA factors (TOTP, WebAuthn, ...).
 * <p>
 * Backup codes are random alphanumeric strings (ambiguous characters {@code 0OIl1} excluded)
 * shown to the user exactly once at enrollment confirmation. They are persisted as
 * PBKDF2-HMAC-SHA256 hashes — that algorithm is preferred over BCrypt here because it does
 * not require an external dependency (it is available via the JDK
 * {@link javax.crypto.SecretKeyFactory}). The hash format is:
 *
 * <pre>pbkdf2-sha256${iterations}${base64(salt)}${base64(hash)}</pre>
 *
 * Verification iterates the full hash list (no short-circuit) to limit information
 * leakage about which slot matched; comparison itself uses {@link MessageDigest#isEqual}.
 */
@Component(service = BackupCodes.class, immediate = true)
public class BackupCodes {

    private static final Logger logger = LoggerFactory.getLogger(BackupCodes.class);

    public static final int CODE_COUNT = 10;
    public static final int CODE_LENGTH = 10;

    /**
     * Maximum length of any user-supplied backup code accepted by {@link #verifyAndIndex}; an
     * up-front cap that prevents CPU amplification through an over-long submitted value. Kept
     * here (rather than referencing a factor constant) so this shared class has no dependency
     * back on any individual factor module.
     */
    public static final int MAX_CODE_LENGTH = 32;

    /** Alphabet without ambiguous characters (0, O, I, l, 1). */
    private static final char[] ALPHABET =
            "ABCDEFGHJKLMNPQRSTUVWXYZ23456789".toCharArray();

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int PBKDF2_ITERATIONS = 120_000;
    private static final int PBKDF2_KEY_BITS = 256;
    private static final int SALT_BYTES = 16;
    private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final String HASH_PREFIX = "pbkdf2-sha256";

    /**
     * Generate {@link #CODE_COUNT} plaintext backup codes. The returned list MUST be shown to
     * the user immediately and never persisted in plaintext.
     */
    public List<String> generate() {
        List<String> codes = new ArrayList<>(CODE_COUNT);
        for (int i = 0; i < CODE_COUNT; i++) {
            codes.add(generateOne());
        }
        return codes;
    }

    private static String generateOne() {
        StringBuilder sb = new StringBuilder(CODE_LENGTH);
        for (int i = 0; i < CODE_LENGTH; i++) {
            sb.append(ALPHABET[RANDOM.nextInt(ALPHABET.length)]);
        }
        return sb.toString();
    }

    /**
     * Hash a single backup code with a fresh random salt.
     */
    public String hash(String code) {
        byte[] salt = new byte[SALT_BYTES];
        RANDOM.nextBytes(salt);
        byte[] hash = pbkdf2(code.toCharArray(), salt, PBKDF2_ITERATIONS, PBKDF2_KEY_BITS);
        Base64.Encoder enc = Base64.getEncoder().withoutPadding();
        return HASH_PREFIX + "$" + PBKDF2_ITERATIONS + "$" + enc.encodeToString(salt)
                + "$" + enc.encodeToString(hash);
    }

    /**
     * Verify a submitted backup code against a list of stored hashes.
     * <p>
     * The full list is iterated (no short-circuit) for constant-ish-time behaviour.
     *
     * @return the index of the matched hash on success (caller is expected to remove it
     *         from the persisted list), empty if no hash matches
     */
    public Optional<Integer> verifyAndIndex(List<String> hashes, String submitted) {
        if (hashes == null || submitted == null) {
            return Optional.empty();
        }
        // Up-front input length cap to prevent CPU amplification via a huge submitted code.
        if (submitted.length() > MAX_CODE_LENGTH) {
            return Optional.empty();
        }
        String normalized = submitted.trim().toUpperCase();
        Integer matchIndex = null;
        for (int i = 0; i < hashes.size(); i++) {
            String stored = hashes.get(i);
            boolean ok = verifyOne(stored, normalized);
            // capture first match but keep iterating
            if (ok && matchIndex == null) {
                matchIndex = i;
            }
        }
        return Optional.ofNullable(matchIndex);
    }

    private static boolean verifyOne(String stored, String submitted) {
        if (stored == null) {
            return false;
        }
        String[] parts = stored.split("\\$");
        if (parts.length != 4 || !HASH_PREFIX.equals(parts[0])) {
            return false;
        }
        int iterations;
        try {
            iterations = Integer.parseInt(parts[1]);
        } catch (NumberFormatException e) {
            return false;
        }
        // Defense-in-depth: refuse hashes weaker than our current minimum cost.
        if (iterations < PBKDF2_ITERATIONS) {
            logger.warn("Refusing backup-code hash with weak iteration count: {} (min {})",
                    iterations, PBKDF2_ITERATIONS);
            return false;
        }
        byte[] salt = Base64.getDecoder().decode(parts[2]);
        byte[] expected = Base64.getDecoder().decode(parts[3]);
        // Defense-in-depth: enforce expected key size matches our key length.
        if (expected.length * 8 != PBKDF2_KEY_BITS) {
            logger.warn("Refusing backup-code hash with unexpected key size: {} bits (expected {})",
                    expected.length * 8, PBKDF2_KEY_BITS);
            return false;
        }
        byte[] actual = pbkdf2(submitted.toCharArray(), salt, iterations, expected.length * 8);
        return MessageDigest.isEqual(expected, actual);
    }

    private static byte[] pbkdf2(char[] password, byte[] salt, int iterations, int keyBits) {
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
            PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyBits);
            try {
                return skf.generateSecret(spec).getEncoded();
            } finally {
                spec.clearPassword();
            }
        } catch (Exception e) {
            throw new IllegalStateException("PBKDF2 derivation failed", e);
        }
    }
}
