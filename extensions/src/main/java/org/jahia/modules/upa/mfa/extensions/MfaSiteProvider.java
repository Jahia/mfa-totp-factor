package org.jahia.modules.upa.mfa.extensions;

/**
 * SPI implemented by every MFA factor (TOTP, WebAuthn, ...) so that the shared, factor-agnostic
 * infrastructure in this bundle — the {@code /cms/login} gate and the login/logout URL provider —
 * can reason about enforcement state and per-site login pages without depending on any individual
 * factor module.
 *
 * <p>This inverts the dependency: {@code totp}/{@code webauthn} depend on {@code extensions} (for
 * {@link BackupCodes}), and in turn register an implementation of this interface. The gate and the
 * provider collect all registered implementations via an OSGi {@code @Reference(MULTIPLE)} and
 * aggregate across them (a site is gated when <em>any</em> factor enforces it; the per-site login
 * URL is the first non-blank value any factor supplies).</p>
 */
public interface MfaSiteProvider {

    /**
     * @param siteKey the JCR site key (never {@code null})
     * @return {@code true} if this factor is enabled <em>and</em> enforces enrollment for the site
     */
    boolean isEnforcedForSite(String siteKey);

    /**
     * @return {@code true} if this factor enforces enrollment on at least one site. Used on the
     * no-resolvable-site code path of the gate, where a per-site decision is not possible.
     */
    boolean isAnySiteEnforced();

    /**
     * @param siteKey the JCR site key (never {@code null})
     * @return a site-relative login URL configured for the site, or {@code null} when this factor
     * has no per-site override (the default).
     */
    default String getLoginUrl(String siteKey) {
        return null;
    }

    /**
     * @param siteKey the JCR site key (never {@code null})
     * @return a site-relative logout URL configured for the site, or {@code null} when this factor
     * has no per-site override (the default).
     */
    default String getLogoutUrl(String siteKey) {
        return null;
    }
}
