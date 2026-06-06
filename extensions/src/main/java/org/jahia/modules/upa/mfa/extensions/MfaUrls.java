package org.jahia.modules.upa.mfa.extensions;

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
