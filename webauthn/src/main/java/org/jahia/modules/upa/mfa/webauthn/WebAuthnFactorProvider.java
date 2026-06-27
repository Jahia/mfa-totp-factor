package org.jahia.modules.upa.mfa.webauthn;

import org.apache.commons.lang3.StringUtils;
import org.jahia.modules.upa.mfa.MfaException;
import org.jahia.modules.upa.mfa.MfaFactorProvider;
import org.jahia.modules.upa.mfa.MfaService;
import org.jahia.modules.upa.mfa.PreparationContext;
import org.jahia.modules.upa.mfa.VerificationContext;
import org.jahia.modules.upa.mfa.extensions.MfaEnforcementDecider;
import org.jahia.modules.upa.mfa.extensions.MfaGlobalPolicy;
import org.jahia.modules.upa.mfa.extensions.MfaSiteProvider;
import org.jahia.services.usermanager.JahiaGroupManagerService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jcr.RepositoryException;
import java.io.IOException;
import java.io.Serializable;
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

    /**
     * Shared, stateless orchestration reused across prepare() calls. Built once in {@link #activate()}
     * after the DS references are bound, over the LIVE {@link #siteProviders} list, so it keeps seeing
     * bind/unbind updates by reference.
     */
    private MfaEnforcementDecider enforcementDecider;

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
        // The per-site activation/scoping shell and the global pick-one decision table both live
        // in the shared MfaEnforcementDecider; WebAuthn only contributes its factor-specific
        // callbacks (its challenge builds an origin-bound assertion ceremony).
        return enforcementDecider.prepare(preparationContext, callbacks());
    }

    /**
     * Build the shared, stateless orchestration once, after all DS references are bound. DS runs the
     * mandatory {@code @Reference} setters and only then activates the component and publishes the
     * service, so the field is safely visible to prepare() without volatile. The live siteProviders
     * list is passed by reference, so the single instance keeps seeing bind/unbind updates.
     */
    @Activate
    public void activate() {
        this.enforcementDecider = new MfaEnforcementDecider(globalPolicy, mfaService, siteProviders);
    }

    /**
     * Factor-specific callbacks the shared orchestration delegates to. The WebAuthn challenge
     * preparation starts an origin-bound assertion ceremony (unlike TOTP's no-op marker).
     */
    private MfaEnforcementDecider.FactorEnforcementCallbacks callbacks() {
        return new MfaEnforcementDecider.FactorEnforcementCallbacks() {
            @Override
            public String factorType() {
                return FACTOR_TYPE;
            }

            @Override
            public boolean isConfiguredForUser(String userId) throws MfaException {
                return isRegistered(userId);
            }

            @Override
            public long getOrStartGraceMillis(String userId, long nowMillis) throws MfaException {
                try {
                    return credentialStore.getOrStartGraceMillis(userId, nowMillis);
                } catch (RepositoryException e) {
                    logger.warn("Failed to read WebAuthn grace state for {}: {}", userId, e.getMessage());
                    throw new MfaException(ERROR_INTERNAL);
                }
            }

            @Override
            public Serializable buildChallengePreparation(String userId) throws MfaException {
                return startAssertion(userId);
            }

            @Override
            public Serializable buildSkippedPreparation() {
                return new WebAuthnPreparationResult(true);
            }

            @Override
            public void recordEnrollmentDenied(String userId, String siteKey, String detail) {
                auditLog.recordEvent("registrationRequired", "denied", userId, siteKey, detail);
            }

            @Override
            public String enrollmentRequiredErrorCode() {
                return ERROR_REGISTRATION_REQUIRED;
            }

            @Override
            public String internalErrorCode() {
                return ERROR_INTERNAL;
            }

            @Override
            public boolean isSiteApplicable(String userId, String siteKey) throws MfaException {
                // Load the per-site settings ONCE and check both enabled and group scope against
                // that single snapshot.
                WebAuthnSiteSettingsStore.WebAuthnSiteSettings settings = loadSettings(siteKey);
                if (!settings.isEnabled()) {
                    return false;
                }
                return WebAuthnFactorProvider.this.isInScope(userId, settings.getEnabledGroups());
            }

            @Override
            public MfaException notConfiguredError(String userId) {
                return new MfaException(ERROR_NOT_REGISTERED, "user", userId);
            }
        };
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
                // Defense in depth: do not rely solely on the yubico library's user-handle binding.
                // The asserted credential MUST belong to the session user, or this is an attempt to
                // complete THIS user's factor with a credential registered to a different account.
                if (!credentialStore.isCredentialOwnedBy(userId, outcome.getCredentialIdB64())) {
                    logger.warn("WebAuthn assertion for user {} matched a credential it does not own - rejecting",
                            userId);
                    ok = false;
                } else {
                    credentialStore.updateOnAssertion(userId, outcome.getCredentialIdB64(), outcome.getNewSignCount());
                }
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

    private WebAuthnSiteSettingsStore.WebAuthnSiteSettings loadSettings(String siteKey) {
        // Per-site settings are now an in-memory read from the file-backed config service (no JCR).
        return siteSettingsStore.load(siteKey);
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
