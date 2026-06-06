package org.jahia.modules.upa.mfa.totp;

import org.apache.commons.codec.binary.Base32;
import org.osgi.service.component.annotations.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Optional;

/**
 * Pure-logic TOTP (RFC 6238) implementation used by the TOTP MFA factor.
 * <p>
 * No JCR / no OSGi state — exposed as an OSGi service so it can be unit-tested
 * and reused by management mutations.
 */
@Component(service = TotpService.class, immediate = true)
public class TotpService {

    public static final int TIME_STEP_SECONDS = 30;
    public static final int DIGITS = 6;
    public static final int DRIFT_WINDOWS = 1;
    public static final int SECRET_BYTES = 20;

    /** Maximum length of any user-supplied code (TOTP or backup) accepted by the surface. */
    public static final int MAX_CODE_LENGTH = 32;

    private static final long DIGITS_MOD = 1_000_000L;
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Base32 BASE32 = new Base32();

    /**
     * Generate a fresh 160-bit secret using {@link SecureRandom}.
     */
    public byte[] generateSecret() {
        byte[] secret = new byte[SECRET_BYTES];
        RANDOM.nextBytes(secret);
        return secret;
    }

    /**
     * Encode bytes as RFC 4648 Base32 without padding.
     */
    public String toBase32(byte[] bytes) {
        String encoded = BASE32.encodeToString(bytes);
        // strip padding for QR readability; padding is still accepted on decode.
        return encoded.replace("=", "");
    }

    /**
     * Decode a Base32 (RFC 4648) string back to raw bytes. Padding is tolerated.
     */
    public byte[] fromBase32(String base32) {
        // Base32 decoder accepts upper-case without padding
        return BASE32.decode(base32.replace(" ", "").toUpperCase());
    }

    /**
     * Generate the HOTP/TOTP code for a given counter (RFC 4226 dynamic truncation).
     *
     * @param secret  the raw HMAC-SHA1 key (typically 20 bytes)
     * @param counter the TOTP counter (= floor(unixTimeSeconds / TIME_STEP_SECONDS))
     * @return zero-padded 6-digit code
     */
    public String generateCode(byte[] secret, long counter) {
        byte[] counterBytes = ByteBuffer.allocate(8).putLong(counter).array();
        byte[] hash;
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(secret, "HmacSHA1"));
            hash = mac.doFinal(counterBytes);
        } catch (Exception e) {
            throw new IllegalStateException("HMAC-SHA1 is required but not available", e);
        }
        int offset = hash[hash.length - 1] & 0x0F;
        int binary = ((hash[offset] & 0x7F) << 24)
                | ((hash[offset + 1] & 0xFF) << 16)
                | ((hash[offset + 2] & 0xFF) << 8)
                | (hash[offset + 3] & 0xFF);
        long otp = binary % DIGITS_MOD;
        String code = Long.toString(otp);
        // left-pad with zeros to exactly DIGITS characters
        if (code.length() < DIGITS) {
            StringBuilder pad = new StringBuilder(DIGITS);
            for (int i = code.length(); i < DIGITS; i++) {
                pad.append('0');
            }
            pad.append(code);
            code = pad.toString();
        }
        return code;
    }

    /**
     * Verify a submitted code against the secret using a ±{@link #DRIFT_WINDOWS} window
     * around T = floor(nowSeconds / TIME_STEP_SECONDS). Rejects any counter that is
     * less-than-or-equal to {@code lastUsedCounter} (replay protection).
     *
     * @return the matched counter on success, empty otherwise
     */
    public Optional<Long> verifyCode(byte[] secret, String submitted, long nowSeconds,
                                     long lastUsedCounter, int driftWindows) {
        if (submitted == null) {
            return Optional.empty();
        }
        String trimmed = submitted.trim();
        if (trimmed.length() != DIGITS) {
            return Optional.empty();
        }
        long t = nowSeconds / TIME_STEP_SECONDS;
        byte[] submittedBytes = trimmed.getBytes(StandardCharsets.US_ASCII);
        Long matched = null;
        // Iterate the entire window without short-circuiting to limit timing leakage about
        // which sub-window matched.
        for (int i = -driftWindows; i <= driftWindows; i++) {
            long counter = t + i;
            if (counter <= lastUsedCounter) {
                continue;
            }
            String candidate = generateCode(secret, counter);
            byte[] candidateBytes = candidate.getBytes(StandardCharsets.US_ASCII);
            if (MessageDigest.isEqual(submittedBytes, candidateBytes) && matched == null) {
                matched = counter;
            }
        }
        return Optional.ofNullable(matched);
    }

    /**
     * Pure-string heuristic used to route a submitted second-factor code: a string of exactly
     * {@link #DIGITS} digits is treated as a TOTP code, anything else as a potential backup code.
     * Lives here (rather than on the shared {@code BackupCodes}) because it is TOTP-specific — it
     * is keyed on the TOTP digit count.
     */
    public static boolean looksLikeBackupCode(String submitted) {
        if (submitted == null) {
            return false;
        }
        String s = submitted.trim();
        if (s.length() != DIGITS) {
            return true;
        }
        for (int i = 0; i < s.length(); i++) {
            if (!Character.isDigit(s.charAt(i))) {
                return true;
            }
        }
        // exactly DIGITS digits -> TOTP code
        return false;
    }

    /**
     * Build the otpauth:// provisioning URI consumed by Google Authenticator-compatible apps.
     * <p>
     * NEVER log the returned URI — it contains the secret.
     */
    public String buildOtpauthUri(String issuer, String account, String base32Secret) {
        String safeIssuer = issuer == null ? "Jahia" : issuer;
        String safeAccount = account == null ? "" : account;
        String label = urlEncode(safeIssuer) + ":" + urlEncode(safeAccount);
        return "otpauth://totp/" + label
                + "?secret=" + base32Secret
                + "&issuer=" + urlEncode(safeIssuer)
                + "&algorithm=SHA1"
                + "&digits=" + DIGITS
                + "&period=" + TIME_STEP_SECONDS;
    }

    private static String urlEncode(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
