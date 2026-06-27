package org.jahia.modules.upa.mfa.extensions;

import org.apache.commons.lang3.StringUtils;
import org.jahia.modules.upa.mfa.MfaException;
import org.jahia.modules.upa.mfa.MfaService;
import org.jahia.modules.upa.mfa.MfaSession;
import org.jahia.modules.upa.mfa.PreparationContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * The factor-agnostic pick-one / enforcement / grace ORCHESTRATION shared by every MFA factor
 * provider (TOTP, WebAuthn, ...). Both providers used to carry a near-verbatim copy of this
 * decision table; it now lives here once and is parameterized by a small set of factor-specific
 * callbacks ({@link FactorEnforcementCallbacks}).
 * <p>
 * Enforcement is GLOBAL ({@link MfaGlobalPolicy}); a user satisfies it with AT LEAST ONE of the
 * enforced factors and the others skip. The decision rows (identical across factors) are:
 * <ul>
 *   <li>another enforced factor was GENUINELY verified in-session &rarr; skip;</li>
 *   <li>the user has this factor configured &rarr; challenge
 *       ({@link FactorEnforcementCallbacks#buildChallengePreparation()});</li>
 *   <li>this factor not configured, but a sibling enforced factor is &rarr; skip (they verify
 *       with that one);</li>
 *   <li>NO enforced factor configured &rarr; allow during the global grace window, then block
 *       with the factor's {@code enrollment_required} error carrying the inline-enrollable
 *       factors offered for the site.</li>
 * </ul>
 * The circular skip-drain guard ({@link SkippablePreparation#isSkipDrained}) is preserved exactly:
 * a factor drained as skipped carries a verified flag but was never challenged, so it must NOT
 * satisfy pick-one for its siblings.
 */
public class MfaEnforcementDecider {

    private static final Logger logger = LoggerFactory.getLogger(MfaEnforcementDecider.class);

    private final MfaGlobalPolicy globalPolicy;
    private final MfaService mfaService;
    private final List<MfaSiteProvider> siteProviders;

    public MfaEnforcementDecider(MfaGlobalPolicy globalPolicy, MfaService mfaService,
                                 List<MfaSiteProvider> siteProviders) {
        this.globalPolicy = globalPolicy;
        this.mfaService = mfaService;
        this.siteProviders = siteProviders;
    }

    /**
     * Factor-specific behavior the shared orchestration delegates to. Keeps the JCR / ceremony
     * details in each factor's own bundle.
     */
    public interface FactorEnforcementCallbacks {

        /** The factor type this provider speaks for (e.g. {@code "totp"}, {@code "webauthn"}). */
        String factorType();

        /** Whether the user has this factor configured (TOTP enrolled / a WebAuthn credential). */
        boolean isConfiguredForUser(String userId) throws MfaException;

        /** Return the epoch-millis the enrollment grace window started (initializing on first call). */
        long getOrStartGraceMillis(String userId, long nowMillis) throws MfaException;

        /**
         * The "the user owns this factor, challenge them" preparation. For TOTP this is a no-op
         * marker; for WebAuthn it starts an assertion ceremony.
         */
        Serializable buildChallengePreparation(String userId) throws MfaException;

        /** A "skip this factor for this session" preparation marker. */
        Serializable buildSkippedPreparation();

        /** Record an audit event when enrollment/registration is denied (grace expired / no grace). */
        void recordEnrollmentDenied(String userId, String siteKey, String detail);

        /** The {@code enrollment_required} / {@code registration_required} error code for this factor. */
        String enrollmentRequiredErrorCode();

        /** The {@code internal_error} error code for this factor (thrown when a sibling read fails closed). */
        String internalErrorCode();

        /**
         * Whether this factor applies to the user on the given site, decided from a SINGLE
         * per-site settings load: the factor must be enabled on the site AND the user must be in
         * scope of the site's policy groups (empty groups = everyone). Returns {@code true} only
         * when BOTH hold; a disabled site OR an out-of-scope user yields {@code false}. Loading the
         * snapshot once is a correctness invariant (the enabled check and the group/scope check
         * must see the same site-settings snapshot).
         */
        boolean isSiteApplicable(String userId, String siteKey) throws MfaException;

        /**
         * Throw the factor's no-site, not-enforced, not-configured terminal error
         * ({@code not_enrolled} / {@code not_registered}). Only reached when there is no site
         * context and the factor is not globally enforced.
         */
        MfaException notConfiguredError(String userId);
    }

    /**
     * The full {@code prepare} decision, including the per-site activation/scoping shell that both
     * factor providers used to mirror. With a resolvable site the factor is skipped when disabled
     * or the user is out of scope, then the site-scoped pick-one rows apply; without one, global
     * enforcement still applies (vanity login URLs carry no {@code /sites/<key>} prefix) and the
     * legacy "challenge the configured user, reject the rest" behavior stands when not enforced.
     */
    public Serializable prepare(PreparationContext preparationContext, FactorEnforcementCallbacks callbacks)
            throws MfaException {
        final String factorType = callbacks.factorType();
        String userId = preparationContext.getSessionContext().getUserId();
        String siteKey = preparationContext.getSessionContext().getSiteKey();

        if (StringUtils.isNotBlank(siteKey)) {
            // Single site-settings snapshot: the enabled check and the group/scope check must read
            // the SAME snapshot, so they are collapsed into one applicability decision (skip when
            // the site is disabled OR the user is out of scope).
            if (!callbacks.isSiteApplicable(userId, siteKey)) {
                logger.debug("{} skipped for user {} (site '{}' not applicable: disabled or not in scope)",
                        factorType, userId, siteKey);
                return callbacks.buildSkippedPreparation();
            }
            return prepareForSite(preparationContext, userId, siteKey, callbacks);
        }

        if (globalPolicy.isEnforced(factorType)) {
            return prepareForGlobalOnly(preparationContext, userId, callbacks);
        }
        if (!callbacks.isConfiguredForUser(userId)) {
            throw callbacks.notConfiguredError(userId);
        }
        return callbacks.buildChallengePreparation(userId);
    }

    /**
     * The enforced decision rows when no site context is available (pick-one semantics minus the
     * per-site activation/scoping rows). Called by the provider after it has determined that the
     * factor is globally enforced and there is no resolvable site.
     */
    public Serializable prepareForGlobalOnly(PreparationContext preparationContext, String userId,
                                             FactorEnforcementCallbacks callbacks) throws MfaException {
        final String factorType = callbacks.factorType();
        if (anotherEnforcedFactorVerified(preparationContext, factorType)) {
            logger.debug("{} skipped for user {} (another enforced factor already verified)",
                    factorType, userId);
            return callbacks.buildSkippedPreparation();
        }
        if (callbacks.isConfiguredForUser(userId)) {
            return callbacks.buildChallengePreparation(userId);
        }
        String sibling = configuredSiblingFactor(userId, callbacks);
        if (sibling != null) {
            warnIfSiblingNotRequired(preparationContext, userId, sibling, factorType);
            logger.debug("{} skipped for user {} (enforced factor {} is configured)",
                    factorType, userId, sibling);
            return callbacks.buildSkippedPreparation();
        }
        return prepareNoEnforcedFactor(userId, null, callbacks);
    }

    /**
     * The site-scoped decision once the site has the factor enabled and the user is in scope.
     * Enforcement is GLOBAL; a user must satisfy it with AT LEAST ONE of the enforced factors.
     */
    public Serializable prepareForSite(PreparationContext preparationContext, String userId, String siteKey,
                                       FactorEnforcementCallbacks callbacks) throws MfaException {
        final String factorType = callbacks.factorType();
        boolean configured = callbacks.isConfiguredForUser(userId);
        if (!globalPolicy.isEnforced(factorType)) {
            if (!configured) {
                logger.debug("{} skipped for user {} (not configured, factor not globally enforced)",
                        factorType, userId);
                return callbacks.buildSkippedPreparation();
            }
            return callbacks.buildChallengePreparation(userId);
        }
        if (anotherEnforcedFactorVerified(preparationContext, factorType)) {
            logger.debug("{} skipped for user {} (another enforced factor already verified)",
                    factorType, userId);
            return callbacks.buildSkippedPreparation();
        }
        if (configured) {
            return callbacks.buildChallengePreparation(userId);
        }
        String sibling = configuredSiblingFactor(userId, callbacks);
        if (sibling != null) {
            warnIfSiblingNotRequired(preparationContext, userId, sibling, factorType);
            logger.debug("{} skipped for user {} (enforced factor {} is configured)",
                    factorType, userId, sibling);
            return callbacks.buildSkippedPreparation();
        }
        return prepareNoEnforcedFactor(userId, siteKey, callbacks);
    }

    /**
     * The user has NONE of the globally enforced factors configured: allow sign-in during the
     * global grace window (per-user start tracked by the factor), then block with the factor's
     * {@code enrollment_required} error carrying the factors the user may enroll inline.
     */
    private Serializable prepareNoEnforcedFactor(String userId, String siteKey,
                                                 FactorEnforcementCallbacks callbacks) throws MfaException {
        long graceDays = globalPolicy.getGraceDays();
        if (graceDays > 0) {
            long now = System.currentTimeMillis();
            long graceStart = callbacks.getOrStartGraceMillis(userId, now);
            if ((now - graceStart) < TimeUnit.DAYS.toMillis(graceDays)) {
                logger.debug("Enrollment grace still active for user {} (started {}, {} days)",
                        userId, graceStart, graceDays);
                return callbacks.buildSkippedPreparation();
            }
        }
        callbacks.recordEnrollmentDenied(userId, siteKey, graceDays > 0 ? "graceExpired" : "noGrace");
        throw new MfaException(callbacks.enrollmentRequiredErrorCode(), "user", userId,
                "enrollableFactors", enrollableFactorsForSite(siteKey));
    }

    /**
     * Whether another globally enforced factor was GENUINELY verified in the current MFA session.
     * A factor drained as skipped also carries the verified flag (the client acknowledges the skip
     * with an empty verify call), but it was never actually challenged &mdash; counting it would
     * let two unchallenged factors skip-drain each other circularly (each pointing at the other)
     * and complete the session with no challenge at all.
     */
    private boolean anotherEnforcedFactorVerified(PreparationContext preparationContext, String factorType) {
        HttpServletRequest request = preparationContext.getHttpServletRequest();
        if (request == null) {
            return false;
        }
        MfaSession session = mfaService.getMfaSession(request);
        if (session == null) {
            return false;
        }
        for (String factor : globalPolicy.getEnforcedFactors()) {
            if (!factorType.equals(factor) && session.isFactorVerified(factor)
                    && !SkippablePreparation.isSkipDrained(session, factor)) {
                return true;
            }
        }
        return false;
    }

    /**
     * The first other globally enforced factor the user has configured (via the sibling
     * {@link MfaSiteProvider}s), or {@code null}. A provider that cannot answer fails CLOSED for
     * sign-in: the error propagates and blocks the login rather than silently skipping a factor.
     */
    private String configuredSiblingFactor(String userId, FactorEnforcementCallbacks callbacks) throws MfaException {
        String factorType = callbacks.factorType();
        for (MfaSiteProvider provider : siteProviders) {
            String type = provider.getFactorType();
            if (factorType.equals(type) || !globalPolicy.isEnforced(type)) {
                continue;
            }
            try {
                if (provider.isConfiguredForUser(userId)) {
                    return type;
                }
            } catch (RuntimeException e) {
                logger.warn("Failed to read {} configuration state for user {}: {}", type, userId, e.getMessage());
                throw new MfaException(callbacks.internalErrorCode());
            }
        }
        return null;
    }

    /**
     * Pick-one hands verification over to the configured sibling factor &mdash; but UPA only ever
     * challenges the factors listed in its own {@code mfaEnabledFactors}. If the sibling is missing
     * there, this sign-in completes with NO second-factor challenge at all: an enforcement bypass
     * caused purely by configuration. Warn loudly instead of blocking &mdash; blocking would
     * dead-end the user, since pre-auth inline enrollment is closed once any enforced factor is
     * owned.
     */
    private void warnIfSiblingNotRequired(PreparationContext preparationContext, String userId,
                                          String sibling, String factorType) {
        List<String> required = preparationContext.getSessionContext().getRequiredFactors();
        if (required == null || !required.contains(sibling)) {
            logger.warn("{} skipped for user {} because enforced factor '{}' is configured, but '{}' is not in "
                    + "UPA's mfaEnabledFactors - this sign-in completes WITHOUT a second-factor challenge. "
                    + "Add it to mfaEnabledFactors (PID org.jahia.modules.upa, typed .config file) so it is "
                    + "actually verified.", factorType, userId, sibling, sibling);
        }
    }

    /**
     * The factors offered for inline enrollment on {@code siteKey}: the globally enforced factors
     * that are enabled on this site (or simply installed, when no site context is available).
     * Factors that cannot be set up from the sign-in flow (e.g. the email-code adapter) are never
     * offered. A provider that cannot answer is simply not offered.
     */
    private String enrollableFactorsForSite(String siteKey) {
        List<String> offered = new ArrayList<>();
        for (String factor : globalPolicy.getEnforcedFactors()) {
            for (MfaSiteProvider provider : siteProviders) {
                if (!factor.equals(provider.getFactorType()) || !provider.isInlineEnrollable()) {
                    continue;
                }
                try {
                    if (StringUtils.isBlank(siteKey) || provider.isEnabledForSite(siteKey)) {
                        offered.add(factor);
                    }
                } catch (RuntimeException e) {
                    logger.warn("Could not evaluate {} availability on site {}: {}", factor, siteKey, e.getMessage());
                }
            }
        }
        return String.join(",", offered);
    }
}
