package org.jahia.modules.upa.mfa.extensions.gql;

import org.apache.commons.lang3.StringUtils;
import org.jahia.modules.upa.mfa.extensions.MfaGlobalPolicy;
import org.jahia.modules.upa.mfa.extensions.MfaUrls;
import org.jahia.modules.upa.mfa.extensions.internal.MfaLoginGateFilter;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Dictionary;
import java.util.List;
import java.util.Locale;

/**
 * Pure read/validate/apply helpers for the global MFA configuration (PID
 * {@code org.jahia.modules.mfa.extensions}) — kept free of OSGi so the validation rules are
 * unit-testable. Errors are reported with stable codes the administration UI maps to messages.
 */
final class MfaExtensionsConfigSupport {

    static final String PID = "org.jahia.modules.mfa.extensions";

    static final String KEY_ENFORCED_FACTORS = "enforcedFactors";
    static final String KEY_GRACE_DAYS = "graceDays";
    static final String KEY_GATE_ENABLED = "loginGate.enabled";
    static final String KEY_GATE_TRUST_FORWARDED_FOR = "loginGate.trustForwardedFor";
    static final String KEY_GATE_WHITELIST = "loginGate.ipWhitelist";
    static final String KEY_LOGIN_URL = "loginUrl";
    static final String KEY_LOGOUT_URL = "logoutUrl";
    static final String KEY_RESET_NOTIFY_EMAIL = "resetRequest.notifyEmail";

    static final String ERROR_UNKNOWN_FACTOR = "mfaExtensions.unknown_factor";
    static final String ERROR_INVALID_GRACE_DAYS = "mfaExtensions.invalid_grace_days";
    static final String ERROR_INVALID_WHITELIST = "mfaExtensions.invalid_whitelist";
    static final String ERROR_INVALID_URL = "mfaExtensions.invalid_url";
    static final String ERROR_INVALID_EMAIL = "mfaExtensions.invalid_email";

    private MfaExtensionsConfigSupport() {
        // utility class
    }

    /** The editable values; a {@code null} field means "leave the key unchanged". */
    static final class Update {
        final List<String> enforcedFactors;
        final Integer graceDays;
        final Boolean loginGateEnabled;
        final String loginGateIpWhitelist;
        final String loginUrl;
        final String logoutUrl;
        final String resetNotifyEmail;
        final Boolean loginGateTrustForwardedFor;

        Update(List<String> enforcedFactors, Integer graceDays, Boolean loginGateEnabled,
               String loginGateIpWhitelist, String loginUrl, String logoutUrl, String resetNotifyEmail,
               Boolean loginGateTrustForwardedFor) {
            this.enforcedFactors = enforcedFactors;
            this.graceDays = graceDays;
            this.loginGateEnabled = loginGateEnabled;
            this.loginGateIpWhitelist = loginGateIpWhitelist;
            this.loginUrl = loginUrl;
            this.logoutUrl = logoutUrl;
            this.resetNotifyEmail = resetNotifyEmail;
            this.loginGateTrustForwardedFor = loginGateTrustForwardedFor;
        }
    }

    /** Build the DTO from the raw ConfigAdmin properties (defaults when absent). */
    static MfaExtensionsConfiguration read(Dictionary<String, Object> properties, List<String> registeredFactors) {
        return new MfaExtensionsConfiguration(
                MfaGlobalPolicy.parseEnforcedFactors(value(properties, KEY_ENFORCED_FACTORS)),
                MfaGlobalPolicy.parseGraceDays(value(properties, KEY_GRACE_DAYS)),
                Boolean.parseBoolean(String.valueOf(value(properties, KEY_GATE_ENABLED))),
                stringValue(properties, KEY_GATE_WHITELIST),
                stringValue(properties, KEY_LOGIN_URL),
                stringValue(properties, KEY_LOGOUT_URL),
                stringValue(properties, KEY_RESET_NOTIFY_EMAIL),
                boolValueDefaultTrue(properties, KEY_GATE_TRUST_FORWARDED_FOR),
                registeredFactors);
    }

    /**
     * Validate the submitted values and apply them onto the existing properties (unknown keys —
     * e.g. {@code felix.fileinstall.filename} — are preserved). A {@code null} field means
     * "leave unchanged"; an empty value clears the key to its default.
     *
     * @throws IllegalArgumentException with one of the stable {@code ERROR_*} codes
     */
    static void applyUpdate(Dictionary<String, Object> properties, Update update,
                            Collection<String> registeredFactors) {
        if (update.enforcedFactors != null) {
            properties.put(KEY_ENFORCED_FACTORS, validateFactors(update.enforcedFactors, registeredFactors));
        }
        if (update.graceDays != null) {
            if (update.graceDays < 0 || update.graceDays > MfaGlobalPolicy.MAX_GRACE_DAYS) {
                throw new IllegalArgumentException(ERROR_INVALID_GRACE_DAYS);
            }
            properties.put(KEY_GRACE_DAYS, String.valueOf(update.graceDays));
        }
        if (update.loginGateEnabled != null) {
            properties.put(KEY_GATE_ENABLED, String.valueOf(update.loginGateEnabled));
        }
        if (update.loginGateTrustForwardedFor != null) {
            properties.put(KEY_GATE_TRUST_FORWARDED_FOR, String.valueOf(update.loginGateTrustForwardedFor));
        }
        if (update.loginGateIpWhitelist != null) {
            properties.put(KEY_GATE_WHITELIST, validateWhitelist(update.loginGateIpWhitelist));
        }
        if (update.loginUrl != null) {
            properties.put(KEY_LOGIN_URL, validateGlobalUrl(update.loginUrl));
        }
        if (update.logoutUrl != null) {
            properties.put(KEY_LOGOUT_URL, validateGlobalUrl(update.logoutUrl));
        }
        if (update.resetNotifyEmail != null) {
            properties.put(KEY_RESET_NOTIFY_EMAIL, validateEmails(update.resetNotifyEmail));
        }
    }

    /**
     * Validate the comma-separated reset-notification recipients: each non-blank entry must look
     * like an email (contain a non-leading {@code @}). Blank clears the key (feature off). Trimmed
     * and deduped on success.
     *
     * @throws IllegalArgumentException ({@link #ERROR_INVALID_EMAIL}) on a malformed entry
     */
    private static String validateEmails(String submitted) {
        List<String> cleaned = new ArrayList<>();
        for (String part : submitted.split(",")) {
            String email = part.trim();
            if (email.isEmpty()) {
                continue;
            }
            if (email.length() < 3 || email.indexOf('@') <= 0) {
                throw new IllegalArgumentException(ERROR_INVALID_EMAIL);
            }
            if (!cleaned.contains(email)) {
                cleaned.add(email);
            }
        }
        return String.join(",", cleaned);
    }

    /**
     * Validate a GLOBAL login/logout URL. Unlike the per-site values these are operator-level, so
     * an absolute {@code http(s)} URL to an external SSO portal is legitimate; but a dangerous
     * scheme ({@code javascript:}, {@code data:}, {@code vbscript:}) is never acceptable, and a
     * relative path must still be a safe server-relative one (no protocol-relative {@code //host}
     * or open-redirect tricks). Blank clears the key to its default.
     *
     * @return the trimmed value (possibly empty), suitable for the {@code .cfg}
     * @throws IllegalArgumentException ({@link #ERROR_INVALID_URL}) when the value is neither a
     *         safe server-relative path nor a well-formed {@code http(s)} absolute URL
     */
    private static String validateGlobalUrl(String submitted) {
        String trimmed = submitted.trim();
        if (trimmed.isEmpty()) {
            return "";
        }
        // Same shared chokepoint the read path (MfaLoginLogoutProvider) uses, so the write and read
        // rules can never drift: a safe server-relative path OR a well-formed http(s) absolute URL
        // with a host, rejecting javascript:/data:/vbscript: and protocol-relative values.
        if (MfaUrls.isSafeGlobalRedirectUrl(trimmed)) {
            return trimmed;
        }
        throw new IllegalArgumentException(ERROR_INVALID_URL);
    }

    /** Every submitted factor must be a registered factor type (a typo = unsatisfiable policy). */
    private static String validateFactors(List<String> submitted, Collection<String> registeredFactors) {
        List<String> cleaned = new ArrayList<>();
        for (String factor : submitted) {
            String normalized = factor == null ? "" : factor.trim().toLowerCase(Locale.ROOT);
            if (normalized.isEmpty()) {
                continue;
            }
            if (!registeredFactors.contains(normalized)) {
                throw new IllegalArgumentException(ERROR_UNKNOWN_FACTOR);
            }
            if (!cleaned.contains(normalized)) {
                cleaned.add(normalized);
            }
        }
        return String.join(",", cleaned);
    }

    /** Every submitted whitelist entry must be a valid IP literal or CIDR block. */
    private static String validateWhitelist(String submitted) {
        long submittedCount = 0;
        for (String part : submitted.split(",")) {
            if (!part.trim().isEmpty()) {
                submittedCount++;
            }
        }
        List<String> parsed = MfaLoginGateFilter.parseWhitelist(submitted);
        if (parsed.size() < submittedCount) {
            throw new IllegalArgumentException(ERROR_INVALID_WHITELIST);
        }
        return String.join(", ", parsed);
    }

    private static Object value(Dictionary<String, Object> properties, String key) {
        return properties == null ? null : properties.get(key);
    }

    private static String stringValue(Dictionary<String, Object> properties, String key) {
        Object raw = value(properties, key);
        return raw == null ? "" : StringUtils.trimToEmpty(raw.toString());
    }

    /** Boolean read defaulting to {@code true} when the key is absent (matches the gate's parsing). */
    private static boolean boolValueDefaultTrue(Dictionary<String, Object> properties, String key) {
        Object raw = value(properties, key);
        return raw == null || Boolean.parseBoolean(raw.toString());
    }
}
