package org.jahia.modules.upa.mfa.extensions;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;

/**
 * Validation helpers for the per-site / global login &amp; logout redirect URLs used by the MFA
 * factor family. Shared so that every writer (the factor admin GraphQL mutations, the site-settings
 * store) and every reader (the {@code MfaLoginLogoutProvider}) enforce exactly the same open-redirect
 * protection — there must be a single chokepoint, not one heuristic per call site.
 */
public final class MfaUrls {

    private MfaUrls() {
        // utility class
    }

    /**
     * Whether the value is a safe GLOBAL login/logout redirect target: either a safe
     * server-relative path (see {@link #isSafeSiteRelativeUrl}) OR a well-formed absolute
     * {@code http(s)} URL with a host (the documented external-SSO use case). Dangerous schemes
     * ({@code javascript:}, {@code data:}, {@code vbscript:}) and protocol-relative values are
     * always rejected. This is the SINGLE rule shared by the write path (admin GraphQL mutation)
     * and the read path ({@code MfaLoginLogoutProvider}) so validation never drifts between them.
     */
    public static boolean isSafeGlobalRedirectUrl(String value) {
        if (value == null) {
            return false;
        }
        String trimmed = value.trim();
        if (trimmed.isEmpty() || hasDangerousScheme(trimmed)) {
            return false;
        }
        if (isSafeSiteRelativeUrl(trimmed)) {
            return true;
        }
        return isWellFormedHttpUrl(trimmed);
    }

    /** Reject the classic XSS/redirect-bait schemes regardless of case or leading whitespace. */
    private static boolean hasDangerousScheme(String value) {
        String lower = value.trim().toLowerCase(Locale.ROOT);
        return lower.startsWith("javascript:") || lower.startsWith("data:") || lower.startsWith("vbscript:");
    }

    /** A well-formed absolute {@code http(s)} URL with a host (the documented external-SSO case). */
    private static boolean isWellFormedHttpUrl(String value) {
        try {
            URI uri = new URI(value);
            String scheme = uri.getScheme();
            return scheme != null
                    && ("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme))
                    && uri.getHost() != null && !uri.getHost().isEmpty();
        } catch (URISyntaxException e) {
            return false;
        }
    }

    /**
     * Whether the value is a safe server-relative redirect target: it must start with a
     * single {@code /}, must NOT be protocol-relative ({@code //host} or the {@code /\host}
     * browser quirk), and must not contain whitespace, control characters or backslashes.
     * Anything else (absolute {@code http(s)://}, {@code javascript:}, …) is rejected —
     * a site admin must never be able to turn the login redirect into an open redirect.
     */
    public static boolean isSafeSiteRelativeUrl(String value) {
        if (value == null || value.isEmpty() || value.charAt(0) != '/') {
            return false;
        }
        if (value.length() > 1 && (value.charAt(1) == '/' || value.charAt(1) == '\\')) {
            return false; // protocol-relative: //host or /\host
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c <= ' ' || c == '\\' || c == 0x7F) {
                return false;
            }
        }
        return true;
    }

    /**
     * Normalize and validate a per-site login/logout URL submitted by a site admin.
     *
     * @return the trimmed value, or {@code null} when blank (= "not configured")
     * @throws IllegalArgumentException when the value is not a safe server-relative path
     *         (see {@link #isSafeSiteRelativeUrl})
     */
    public static String validateSiteRelativeUrl(String value) {
        String trimmed = value == null ? null : value.trim();
        if (trimmed == null || trimmed.isEmpty()) {
            return null;
        }
        if (!isSafeSiteRelativeUrl(trimmed)) {
            throw new IllegalArgumentException(
                    "URL must be a server-relative path starting with '/' (got a value that is absolute, "
                            + "protocol-relative, or contains illegal characters)");
        }
        return trimmed;
    }
}
