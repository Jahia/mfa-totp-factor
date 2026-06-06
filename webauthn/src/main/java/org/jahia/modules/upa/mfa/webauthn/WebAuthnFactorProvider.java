package org.jahia.modules.upa.mfa.webauthn;

import org.apache.commons.lang3.StringUtils;
import org.jahia.modules.upa.mfa.MfaException;
import org.jahia.modules.upa.mfa.MfaFactorProvider;
import org.jahia.modules.upa.mfa.MfaService;
import org.jahia.modules.upa.mfa.MfaSession;
import org.jahia.modules.upa.mfa.PreparationContext;
import org.jahia.modules.upa.mfa.VerificationContext;
import org.jahia.modules.upa.mfa.extensions.MfaGlobalPolicy;
import org.jahia.modules.upa.mfa.extensions.MfaSiteProvider;
import org.jahia.services.usermanager.JahiaGroupManagerService;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jcr.RepositoryException;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Phishing-resistant WebAuthn / FIDO2 second factor (W3C WebAuthn Level 2).
 * <p>
 * Authentication flow (mirrors {@code TotpFactorProvider} for the per-site enable/enforce/grace
 * policy, but the verification is an origin-bound assertion ceremony rather than a code):
 * <ul>
 *   <li>{@link #prepare} — when the site enables WebAuthn for an in-scope, registered user, start
 *       an assertion ({@code navigator.credentials.get}) with a fresh challenge and hand the
 *       options to the client; otherwise skip / enforce registration (with optional grace).</li>
 *   <li>{@link #verify} — validate the authenticator assertion (signature, origin/rpId binding,
 *       challenge match) and persist the new signature counter for clone detection.</li>
 * </ul>
 * Registration ({@code navigator.credentials.create}) is a self-service dashboard operation on
 * the GraphQL mutation, not part of this login provider.
 */
@Component(service = MfaFactorProvider.class, immediate = true)
public class WebAuthnFactorProvider implements MfaFactorProvider {

    private static final Logger logger = LoggerFactory.getLogger(WebAuthnFactorProvider.class);

    public static final String FACTOR_TYPE = "webauthn";

    public static final String ERROR_NOT_REGISTERED = "factor.webauthn.not_registered";
    public static final String ERROR_REGISTRATION_REQUIRED = "factor.webauthn.registration_required";
    public static final String ERROR_VERIFICATION_DATA_REQUIRED = "factor.webauthn.verification_data_required";
    public static final String ERROR_INTERNAL = "factor.webauthn.internal_error";

    private WebAuthnService webAuthnService;
    private WebAuthnCredentialStore credentialStore;
    private WebAuthnSiteSettingsStore siteSettingsStore;
    private WebAuthnAuditLog auditLog;
    private JahiaGroupManagerService groupManagerService;
    private MfaGlobalPolicy globalPolicy;
    private MfaService mfaService;

    /** Every factor's per-user configuration view, for the cross-factor "at least one" decision. */
    private final List<MfaSiteProvider> siteProviders = new CopyOnWriteArrayList<>();

    @Reference
    public void setWebAuthnService(WebAuthnService webAuthnService) { this.webAuthnService = webAuthnService; }

    @Reference
    public void setCredentialStore(WebAuthnCredentialStore credentialStore) { this.credentialStore = credentialStore; }

    @Reference
    public void setSiteSettingsStore(WebAuthnSiteSettingsStore siteSettingsStore) { this.siteSettingsStore = siteSettingsStore; }

    @Reference
    public void setAuditLog(WebAuthnAuditLog auditLog) { this.auditLog = auditLog; }

    @Reference
    public void setGroupManagerService(JahiaGroupManagerService groupManagerService) { this.groupManagerService = groupManagerService; }

    @Reference
    public void setGlobalPolicy(MfaGlobalPolicy globalPolicy) { this.globalPolicy = globalPolicy; }

    @Reference
    public void setMfaService(MfaService mfaService) { this.mfaService = mfaService; }

    @Reference(service = MfaSiteProvider.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC)
    public void bindSiteProvider(MfaSiteProvider provider) { siteProviders.add(provider); }

    public void unbindSiteProvider(MfaSiteProvider provider) { siteProviders.remove(provider); }

    @Override
    public String getFactorType() {
        return FACTOR_TYPE;
    }

    @Override
    public Serializable prepare(PreparationContext preparationContext) throws MfaException {
        String userId = preparationContext.getSessionContext().getUserId();
        String siteKey = preparationContext.getSessionContext().getSiteKey();

        if (StringUtils.isNotBlank(siteKey)) {
            WebAuthnSiteSettingsStore.WebAuthnSiteSettings settings = loadSettings(siteKey);
            if (!settings.isEnabled()) {
                logger.debug("WebAuthn skipped for user {} (site '{}' disabled)", userId, siteKey);
                return new WebAuthnPreparationResult(true);
            }
            if (!isInScope(userId, settings.getEnabledGroups())) {
                logger.debug("WebAuthn skipped for user {} (not in any policy group on '{}')", userId, siteKey);
                return new WebAuthnPreparationResult(true);
            }
            return prepareForSite(preparationContext, userId, siteKey);
        }

        // No site context → require a registered user.
        if (!isRegistered(userId)) {
            throw new MfaException(ERROR_NOT_REGISTERED, "user", userId);
        }
        return startAssertion(userId);
    }

    /**
     * The site-scoped decision once the site has WebAuthn enabled and the user is in scope.
     * Enforcement is GLOBAL ({@link MfaGlobalPolicy}); a user must satisfy it with AT LEAST ONE
     * of the enforced factors — the others skip (mirrors {@code TotpFactorProvider}).
     */
    private Serializable prepareForSite(PreparationContext preparationContext, String userId, String siteKey)
            throws MfaException {
        boolean registered = isRegistered(userId);
        if (!globalPolicy.isEnforced(FACTOR_TYPE)) {
            if (!registered) {
                logger.debug("WebAuthn skipped for user {} (not registered, factor not globally enforced)", userId);
                return new WebAuthnPreparationResult(true);
            }
            return startAssertion(userId);
        }
        if (anotherEnforcedFactorVerified(preparationContext)) {
            logger.debug("WebAuthn skipped for user {} (another enforced factor already verified)", userId);
            return new WebAuthnPreparationResult(true);
        }
        if (registered) {
            return startAssertion(userId);
        }
        if (anotherEnforcedFactorConfigured(userId)) {
            logger.debug("WebAuthn skipped for user {} (another enforced factor is configured)", userId);
            return new WebAuthnPreparationResult(true);
        }
        return prepareNoEnforcedFactor(userId, siteKey);
    }

    /**
     * The user has NONE of the globally enforced factors configured: allow sign-in during the
     * global grace window, then block with {@code registration_required} carrying the factors
     * the user may enroll inline.
     */
    private Serializable prepareNoEnforcedFactor(String userId, String siteKey) throws MfaException {
        long graceDays = globalPolicy.getGraceDays();
        if (graceDays > 0) {
            long now = System.currentTimeMillis();
            long graceStart;
            try {
                graceStart = credentialStore.getOrStartGraceMillis(userId, now);
            } catch (RepositoryException e) {
                logger.warn("Failed to read WebAuthn grace state for {}: {}", userId, e.getMessage());
                throw new MfaException(ERROR_INTERNAL);
            }
            if ((now - graceStart) < graceDays * 24L * 60L * 60L * 1000L) {
                return new WebAuthnPreparationResult(true);
            }
        }
        auditLog.recordEvent("registrationRequired", "denied", userId, siteKey,
                graceDays > 0 ? "graceExpired" : "noGrace");
        throw new MfaException(ERROR_REGISTRATION_REQUIRED, "user", userId,
                "enrollableFactors", enrollableFactorsForSite(siteKey));
    }

    /** Whether another globally enforced factor is already verified in the current MFA session. */
    private boolean anotherEnforcedFactorVerified(PreparationContext preparationContext) {
        HttpServletRequest request = preparationContext.getHttpServletRequest();
        if (request == null) {
            return false;
        }
        MfaSession session = mfaService.getMfaSession(request);
        if (session == null) {
            return false;
        }
        for (String factor : globalPolicy.getEnforcedFactors()) {
            if (!FACTOR_TYPE.equals(factor) && session.isFactorVerified(factor)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Whether the user has another globally enforced factor configured (via the sibling
     * {@code MfaSiteProvider}s). A provider that cannot answer fails CLOSED for sign-in.
     */
    private boolean anotherEnforcedFactorConfigured(String userId) throws MfaException {
        for (MfaSiteProvider provider : siteProviders) {
            String type = provider.getFactorType();
            if (FACTOR_TYPE.equals(type) || !globalPolicy.isEnforced(type)) {
                continue;
            }
            try {
                if (provider.isConfiguredForUser(userId)) {
                    return true;
                }
            } catch (RuntimeException e) {
                logger.warn("Failed to read {} configuration state for user {}: {}", type, userId, e.getMessage());
                throw new MfaException(ERROR_INTERNAL);
            }
        }
        return false;
    }

    /**
     * The factors offered for inline enrollment on {@code siteKey}: the globally enforced factors
     * that are enabled on this site. A provider that cannot answer is simply not offered.
     */
    private String enrollableFactorsForSite(String siteKey) {
        List<String> offered = new ArrayList<>();
        for (String factor : globalPolicy.getEnforcedFactors()) {
            for (MfaSiteProvider provider : siteProviders) {
                if (!factor.equals(provider.getFactorType())) {
                    continue;
                }
                try {
                    if (provider.isEnabledForSite(siteKey)) {
                        offered.add(factor);
                    }
                } catch (RuntimeException e) {
                    logger.warn("Could not evaluate {} availability on site {}: {}", factor, siteKey, e.getMessage());
                }
            }
        }
        return String.join(",", offered);
    }

    private Serializable startAssertion(String userId) throws MfaException {
        try {
            WebAuthnService.AssertionCeremony ceremony = webAuthnService.startAssertion(userId);
            return new WebAuthnPreparationResult(false, ceremony.getRequestJson(), ceremony.getClientOptionsJson());
        } catch (IOException e) {
            logger.warn("Failed to start WebAuthn assertion for {}: {}", userId, e.getMessage());
            throw new MfaException(ERROR_INTERNAL);
        }
    }

    @Override
    public boolean verify(VerificationContext verificationContext) throws MfaException {
        Serializable prep = verificationContext.getPreparationResult();
        if (prep instanceof WebAuthnPreparationResult && ((WebAuthnPreparationResult) prep).isSkipped()) {
            return true;
        }
        if (!(prep instanceof WebAuthnPreparationResult)) {
            throw new MfaException(ERROR_INTERNAL);
        }
        String requestJson = ((WebAuthnPreparationResult) prep).getRequestJson();

        String userId = verificationContext.getSessionContext().getUserId();
        Serializable raw = verificationContext.getVerificationData();
        if (!(raw instanceof String) || StringUtils.isBlank((String) raw)) {
            throw new MfaException(ERROR_VERIFICATION_DATA_REQUIRED);
        }
        String responseJson = (String) raw;
        String siteKey = verificationContext.getSessionContext().getSiteKey();

        boolean ok;
        try {
            WebAuthnService.AssertionOutcome outcome = webAuthnService.finishAssertion(requestJson, responseJson);
            ok = outcome.isSuccess();
            if (ok) {
                credentialStore.updateOnAssertion(userId, outcome.getCredentialIdB64(), outcome.getNewSignCount());
            }
        } catch (IOException e) {
            logger.warn("WebAuthn assertion verification error for {}: {}", userId, e.getMessage());
            ok = false;
        } catch (RepositoryException e) {
            logger.warn("Failed to persist WebAuthn sign counter for {}: {}", userId, e.getMessage());
            // Assertion was valid but the counter couldn't be recorded — refuse, to preserve
            // clone-detection integrity.
            ok = false;
        }
        auditLog.recordEvent("verify", ok ? "success" : "failure", userId, siteKey, null);
        return ok;
    }

    private WebAuthnSiteSettingsStore.WebAuthnSiteSettings loadSettings(String siteKey) throws MfaException {
        try {
            return siteSettingsStore.load(siteKey);
        } catch (RepositoryException e) {
            logger.warn("Failed to load WebAuthn site settings for {}: {}", siteKey, e.getMessage());
            throw new MfaException(ERROR_INTERNAL);
        }
    }

    private boolean isInScope(String userId, java.util.List<String> enabledGroups) throws MfaException {
        try {
            return credentialStore.isMemberOfAnyGroup(userId, enabledGroups, groupManagerService);
        } catch (RepositoryException e) {
            logger.warn("Failed to check group membership for {}: {}", userId, e.getMessage());
            throw new MfaException(ERROR_INTERNAL);
        }
    }

    private boolean isRegistered(String userId) throws MfaException {
        try {
            return credentialStore.hasCredentials(userId);
        } catch (RepositoryException e) {
            logger.warn("Failed to read WebAuthn credentials for {}: {}", userId, e.getMessage());
            throw new MfaException(ERROR_INTERNAL);
        }
    }
}
