package org.jahia.modules.upa.mfa.extensions;

/**
 * SPI implemented by every MFA factor (TOTP, WebAuthn, ...) so that the shared, factor-agnostic
 * infrastructure in this bundle (the {@code /cms/login} gate and the global enforcement policy,
 * {@link MfaGlobalPolicy}) can reason about per-site activation and per-user configuration state
 * without depending on any individual factor module. Per-site login/logout URLs are no longer a
 * factor concern: they are factor-agnostic and read directly from {@link MfaSiteConfigService}.
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
     * @return {@code true} (the default) if the user can set this factor up from the inline
     * enrollment step of the sign-in flow (scan a QR code, register a passkey, ...).
     * {@code false} for factors whose "configured" state is not user-enrollable at login —
     * e.g. the email factor, whose configuration is simply a {@code j:email} profile property
     * the sign-in flow cannot add. Such factors are never offered by the inline-enrollment
     * chooser (there is no enrollment UI behind the button).
     */
    default boolean isInlineEnrollable() {
        return true;
    }

    /**
     * @return {@code false} (the default) when this provider is implemented by the factor's own
     * bundle, whose UPA factor provider speaks the pick-one skip protocol
     * ({@link SkippablePreparation}) and therefore releases itself once another enforced factor
     * is genuinely verified. {@code true} for pure ADAPTERS that only speak ABOUT a factor
     * implemented elsewhere (UPA's built-in email_code): the underlying UPA provider cannot skip
     * itself, so the {@link MfaForeignFactorDrain} must release it instead.
     */
    default boolean isForeignFactor() {
        return false;
    }
}
