package org.jahia.modules.upa.mfa.totp;

import org.apache.commons.lang3.StringUtils;
import org.jahia.modules.upa.mfa.MfaException;
import org.jahia.modules.upa.mfa.MfaFactorProvider;
import org.jahia.modules.upa.mfa.MfaService;
import org.jahia.modules.upa.mfa.PreparationContext;
import org.jahia.modules.upa.mfa.VerificationContext;
import org.jahia.modules.upa.mfa.extensions.BackupCodes;
import org.jahia.modules.upa.mfa.extensions.MfaEnforcementDecider;
import org.jahia.modules.upa.mfa.extensions.MfaGlobalPolicy;
import org.jahia.modules.upa.mfa.extensions.MfaSiteProvider;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jcr.RepositoryException;
import java.io.Serializable;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * TOTP MFA factor provider (RFC 6238).
 * <p>
 * Authentication flow:
 * <ul>
 *     <li>{@link #prepare(PreparationContext)} — no-op (TOTP codes are generated client-side
 *         by the authenticator app). Verifies the user is actually enrolled and returns a
 *         marker preparation result.</li>
 *     <li>{@link #verify(VerificationContext)} — accepts either a 6-digit TOTP code or a
 *         backup code. Replays are rejected via {@code lastUsedCounter}; backup codes are
 *         consumed (single-use).</li>
 * </ul>
 * Enrollment / management operations live on the GraphQL mutation, not on this provider.
 */
@Component(service = MfaFactorProvider.class, immediate = true)
public class TotpFactorProvider implements MfaFactorProvider {

    private static final Logger logger = LoggerFactory.getLogger(TotpFactorProvider.class);

    public static final String FACTOR_TYPE = "totp";

    public static final String ERROR_NOT_ENROLLED = "factor.totp.not_enrolled";
    public static final String ERROR_ENROLLMENT_REQUIRED = "factor.totp.enrollment_required";
    public static final String ERROR_VERIFICATION_CODE_REQUIRED = "factor.totp.verification_code_required";
    public static final String ERROR_INTERNAL = "factor.totp.internal_error";

    private TotpService totpService;
    private TotpUserStore userStore;
    private BackupCodes backupCodes;
    private TotpSiteSettingsStore siteSettingsStore;
    private TotpAuditLog auditLog;
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
    public void setTotpService(TotpService totpService) { this.totpService = totpService; }

    @Reference
    public void setUserStore(TotpUserStore userStore) { this.userStore = userStore; }

    @Reference
    public void setBackupCodes(BackupCodes backupCodes) { this.backupCodes = backupCodes; }

    @Reference
    public void setSiteSettingsStore(TotpSiteSettingsStore siteSettingsStore) { this.siteSettingsStore = siteSettingsStore; }

    @Reference
    public void setAuditLog(TotpAuditLog auditLog) { this.auditLog = auditLog; }

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
        // in the shared MfaEnforcementDecider; TOTP only contributes its factor-specific callbacks.
        // (Crucially, when siteKey is absent we NEVER short-circuit verification - see notConfiguredError.)
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
     * Factor-specific callbacks the shared orchestration delegates to. The TOTP challenge
     * preparation is a no-op marker (codes are generated client-side by the authenticator app).
     */
    private MfaEnforcementDecider.FactorEnforcementCallbacks callbacks() {
        return new MfaEnforcementDecider.FactorEnforcementCallbacks() {
            @Override
            public String factorType() {
                return FACTOR_TYPE;
            }

            @Override
            public boolean isConfiguredForUser(String userId) throws MfaException {
                return isEnrolled(userId);
            }

            @Override
            public long getOrStartGraceMillis(String userId, long nowMillis) throws MfaException {
                try {
                    return userStore.getOrStartGraceMillis(userId, nowMillis);
                } catch (RepositoryException e) {
                    logger.warn("Failed to read TOTP grace state for user {}: {}", userId, e.getMessage());
                    throw new MfaException(ERROR_INTERNAL);
                }
            }

            @Override
            public Serializable buildChallengePreparation(String userId) {
                return new TotpPreparationResult();
            }

            @Override
            public Serializable buildSkippedPreparation() {
                return new TotpPreparationResult(true);
            }

            @Override
            public void recordEnrollmentDenied(String userId, String siteKey, String detail) {
                auditLog.recordEvent("enrollmentRequired", "denied", userId, siteKey, detail);
            }

            @Override
            public String enrollmentRequiredErrorCode() {
                return ERROR_ENROLLMENT_REQUIRED;
            }

            @Override
            public String internalErrorCode() {
                return ERROR_INTERNAL;
            }

            @Override
            public boolean isSiteApplicable(String userId, String siteKey) throws MfaException {
                // Load the per-site settings ONCE and check both enabled and group scope against
                // that single snapshot.
                TotpSiteSettingsStore.TotpSiteSettings settings = siteSettingsStore.load(siteKey);
                if (!settings.isEnabled()) {
                    return false;
                }
                try {
                    return userStore.isMemberOfAnyGroup(userId, settings.getEnabledGroups());
                } catch (RepositoryException e) {
                    logger.warn("Failed to check group membership for user {}: {}", userId, e.getMessage());
                    throw new MfaException(ERROR_INTERNAL);
                }
            }

            @Override
            public MfaException notConfiguredError(String userId) {
                return new MfaException(ERROR_NOT_ENROLLED, "user", userId);
            }
        };
    }

    /**
     * Lightweight enrollment check that wraps the JCR exception into an {@link MfaException}.
     * Does NOT load the Base32 secret into the heap.
     */
    private boolean isEnrolled(String userId) throws MfaException {
        try {
            return userStore.isEnrolled(userId);
        } catch (RepositoryException e) {
            logger.warn("Failed to load TOTP user settings for {}: {}", userId, e.getMessage());
            throw new MfaException(ERROR_INTERNAL);
        }
    }

    @Override
    public boolean verify(VerificationContext verificationContext) throws MfaException {
        // If prepare() marked the factor as skipped (site has TOTP disabled, or user not
        // enrolled and enforcement off), any submission is accepted — the factor is a
        // no-op for this session.
        Serializable prep = verificationContext.getPreparationResult();
        if (prep instanceof TotpPreparationResult && ((TotpPreparationResult) prep).isSkipped()) {
            return true;
        }

        String userId = verificationContext.getSessionContext().getUserId();
        Serializable raw = verificationContext.getVerificationData();
        if (!(raw instanceof String)) {
            throw new MfaException(ERROR_VERIFICATION_CODE_REQUIRED);
        }
        String submitted = ((String) raw).trim();
        if (StringUtils.isEmpty(submitted)) {
            throw new MfaException(ERROR_VERIFICATION_CODE_REQUIRED);
        }

        TotpUserStore.TotpUserSettings settings;
        try {
            settings = userStore.load(userId);
        } catch (RepositoryException e) {
            logger.warn("Failed to load TOTP settings for user {}: {}", userId, e.getMessage());
            throw new MfaException(ERROR_INTERNAL);
        }
        if (!settings.isEnrolled() || StringUtils.isEmpty(settings.getSecretBase32())) {
            throw new MfaException(ERROR_NOT_ENROLLED, "user", userId);
        }

        boolean backupCode = TotpService.looksLikeBackupCode(submitted);
        boolean ok = backupCode
                ? verifyBackupCode(userId, submitted)
                : verifyTotpCode(userId, submitted);
        String siteKey = verificationContext.getSessionContext().getSiteKey();
        auditLog.recordEvent("verify", ok ? "success" : "failure", userId, siteKey,
                backupCode ? "backupCode" : "totp");
        return ok;
    }

    private boolean verifyTotpCode(String userId, String submitted) {
        // Go through the centralized verify-and-consume chokepoint so the matched counter is
        // persisted atomically in the SAME JCR transaction that reads lastUsedCounter — this
        // is what guarantees replay protection at login. Do NOT call verifyCode directly here.
        long now = System.currentTimeMillis() / 1000L;
        try {
            Optional<Long> matched = userStore.verifyAndConsumeTotp(userId, totpService, submitted,
                    now, TotpService.DRIFT_WINDOWS);
            if (matched.isPresent()) {
                return true;
            }
        } catch (RepositoryException e) {
            logger.warn("Failed to verify/consume TOTP for user {}: {}", userId, e.getMessage());
            // If we cannot atomically record consumption, refuse — preserves replay protection.
            return false;
        }
        logger.warn("TOTP verification failed for user {}", userId);
        return false;
    }

    private boolean verifyBackupCode(String userId, String submitted) {
        // Go through the atomic verify-and-consume chokepoint: the hash list is re-read and
        // the matched hash removed in the SAME JCR transaction, so two parallel submissions
        // of the same backup code cannot both succeed (single-use guarantee).
        try {
            if (userStore.verifyAndConsumeBackupCode(userId, backupCodes, submitted)) {
                return true;
            }
        } catch (RepositoryException e) {
            logger.warn("Failed to verify/consume backup code for user {}: {}", userId, e.getMessage());
            // If we cannot atomically remove the hash, refuse the login — single-use takes precedence.
            return false;
        }
        logger.warn("Backup code verification failed for user {}", userId);
        return false;
    }
}
