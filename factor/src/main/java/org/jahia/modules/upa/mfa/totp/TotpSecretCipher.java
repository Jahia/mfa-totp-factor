package org.jahia.modules.upa.mfa.totp;

import org.jahia.settings.SettingsBean;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Modified;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.EnumSet;
import java.util.Map;
import java.util.Set;

/**
 * Encrypts the TOTP shared secret at rest with AES-GCM.
 * <p>
 * A TOTP secret cannot be hashed (verification must recompute codes from it), so it is
 * encrypted instead. The encryption key is resolved, in order:
 * <ol>
 *   <li>the Karaf configuration property {@code secret.encryption.key} (PID
 *       {@code org.jahia.modules.totp}) — a Base64-encoded 256-bit key supplied by the
 *       operator; or</li>
 *   <li>an auto-generated key persisted to {@code <jahiaVarDir>/mfa-totp-factor/secret.key}
 *       — which lives on the filesystem, <b>outside the JCR datastore</b>, so a database or
 *       JCR backup leak no longer discloses the secrets.</li>
 * </ol>
 * Stored format: {@code v1:<base64(iv)>:<base64(ciphertext||tag)>}. Values that do not carry
 * the {@code v1:} prefix are treated as legacy plaintext (Base32) and returned as-is, so
 * pre-existing enrollments keep working; they are transparently re-encrypted on the next write.
 */
@Component(service = TotpSecretCipher.class, immediate = true, configurationPid = "org.jahia.modules.totp")
public class TotpSecretCipher {

    private static final Logger logger = LoggerFactory.getLogger(TotpSecretCipher.class);

    static final String PREFIX_V1 = "v1:";
    private static final String CONFIG_KEY_PROPERTY = "secret.encryption.key";
    private static final String KEY_FILE_RELATIVE = "mfa-totp-factor/secret.key";

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int KEY_BITS = 256;
    private static final int GCM_IV_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;

    private final SecureRandom secureRandom = new SecureRandom();
    private volatile SecretKey key;

    @Activate
    @Modified
    public void activate(Map<String, Object> properties) {
        this.key = resolveKey(properties);
    }

    /**
     * Encrypt a Base32 secret. Returns the {@code v1:iv:ciphertext} envelope.
     */
    public String encrypt(String plaintextBase32) {
        if (plaintextBase32 == null) {
            return null;
        }
        try {
            byte[] iv = new byte[GCM_IV_BYTES];
            secureRandom.nextBytes(iv);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
            byte[] ciphertext = cipher.doFinal(plaintextBase32.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            Base64.Encoder enc = Base64.getEncoder();
            return PREFIX_V1 + enc.encodeToString(iv) + ":" + enc.encodeToString(ciphertext);
        } catch (Exception e) {
            // Never log the plaintext.
            throw new IllegalStateException("Failed to encrypt TOTP secret", e);
        }
    }

    /**
     * Decrypt a stored value. If it is not in the {@code v1:} envelope it is assumed to be a
     * legacy plaintext Base32 secret and returned unchanged (backward compatibility).
     */
    public String decrypt(String stored) {
        if (stored == null) {
            return null;
        }
        if (!isEncrypted(stored)) {
            return stored; // legacy plaintext
        }
        try {
            String[] parts = stored.split(":", 3);
            if (parts.length != 3) {
                throw new IllegalArgumentException("Malformed encrypted secret envelope");
            }
            Base64.Decoder dec = Base64.getDecoder();
            byte[] iv = dec.decode(parts[1]);
            byte[] ciphertext = dec.decode(parts[2]);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_BITS, iv));
            byte[] plain = cipher.doFinal(ciphertext);
            return new String(plain, java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to decrypt TOTP secret", e);
        }
    }

    /** True if the value carries the encryption envelope (i.e. is NOT legacy plaintext). */
    public boolean isEncrypted(String stored) {
        return stored != null && stored.startsWith(PREFIX_V1);
    }

    private SecretKey resolveKey(Map<String, Object> properties) {
        Object configured = properties == null ? null : properties.get(CONFIG_KEY_PROPERTY);
        if (configured instanceof String && !((String) configured).trim().isEmpty()) {
            try {
                byte[] raw = Base64.getDecoder().decode(((String) configured).trim());
                logger.info("TOTP secret encryption key loaded from Karaf configuration");
                return new SecretKeySpec(raw, ALGORITHM);
            } catch (IllegalArgumentException e) {
                logger.error("Configured {} is not valid Base64; falling back to the key file", CONFIG_KEY_PROPERTY);
            }
        }
        return loadOrCreateKeyFile();
    }

    private synchronized SecretKey loadOrCreateKeyFile() {
        Path keyFile = resolveKeyFilePath();
        try {
            if (Files.exists(keyFile)) {
                byte[] raw = Base64.getDecoder().decode(new String(Files.readAllBytes(keyFile),
                        java.nio.charset.StandardCharsets.UTF_8).trim());
                return new SecretKeySpec(raw, ALGORITHM);
            }
            // Generate, then persist with owner-only permissions where supported.
            KeyGenerator kg = KeyGenerator.getInstance(ALGORITHM);
            kg.init(KEY_BITS, secureRandom);
            SecretKey generated = kg.generateKey();
            Files.createDirectories(keyFile.getParent());
            Files.write(keyFile, Base64.getEncoder().encodeToString(generated.getEncoded())
                    .getBytes(java.nio.charset.StandardCharsets.UTF_8), StandardOpenOption.CREATE_NEW);
            restrictPermissions(keyFile);
            logger.info("Generated a new TOTP secret encryption key at {}", keyFile);
            return generated;
        } catch (Exception e) {
            throw new IllegalStateException("Unable to load or create the TOTP secret encryption key at " + keyFile, e);
        }
    }

    private Path resolveKeyFilePath() {
        String varDir = SettingsBean.getInstance().getJahiaVarDiskPath();
        return Paths.get(varDir, KEY_FILE_RELATIVE);
    }

    private static void restrictPermissions(Path keyFile) {
        try {
            Set<PosixFilePermission> ownerOnly = EnumSet.of(
                    PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);
            Files.setPosixFilePermissions(keyFile, ownerOnly);
        } catch (UnsupportedOperationException | IOException e) {
            // Non-POSIX filesystem (e.g. Windows) — best effort only.
            logger.debug("Could not restrict permissions on {}: {}", keyFile, e.getMessage());
        }
    }
}
