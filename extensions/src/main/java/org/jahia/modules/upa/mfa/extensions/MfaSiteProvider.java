package org.jahia.modules.upa.mfa.extensions;

/**
 * SPI implemented by every MFA factor (TOTP, WebAuthn, ...) so that the shared, factor-agnostic
 * infrastructure in this bundle — the {@code /cms/login} gate, the login/logout URL provider and
 * the global enforcement policy ({@link MfaGlobalPolicy}) — can reason about per-site activation,
 * per-user configuration state and per-site login pages without depending on any individual
 * factor module.
 *
 * <p>This inverts the dependency: {@code totp}/{@code webauthn} depend on {@code extensions} (for
 * {@link BackupCodes} and {@link MfaGlobalPolicy}), and in turn register an implementation of this
 * interface. Consumers collect all registered implementations via an OSGi
 * {@code @Reference(MULTIPLE)} and aggregate across them.</p>
 *
 * <p><b>Error contract:</b> on an unrecoverable backend error (e.g. an unhealthy repository) the
 * boolean methods should throw an unchecked exception rather than guess — access-control callers
 * (the login gate) treat a throwing provider as fail-CLOSED, while best-effort callers (the URL
 * provider) treat it as "no answer".</p>
 */
public interface MfaSiteProvider {

    /**
     * @return the factor type this provider speaks for (e.g. {@code "totp"}, {@code "webauthn"}),
     * matching the type registered with UPA's factor registry and listed in
     * {@link MfaGlobalPolicy#getEnforcedFactors()}.
     */
    String getFactorType();

    /**
     * @param siteKey the JCR site key (never {@code null})
     * @return {@code true} if this factor is enabled for the site (per-site activation;
     * enforcement is global — see {@link MfaGlobalPolicy})
     */
    boolean isEnabledForSite(String siteKey);

    /**
     * @return {@code true} if this factor is enabled on at least one site. Used on the
     * no-resolvable-site code path of the gate, where a per-site decision is not possible.
     */
    boolean isAnySiteEnabled();

    /**
     * @param userId the user identifier (never {@code null})
     * @return {@code true} if the user has this factor configured (enrolled in TOTP, has a
     * WebAuthn credential, ...). Used for the cross-factor "at least one enforced factor
     * configured" decision.
     */
    boolean isConfiguredForUser(String userId);

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
