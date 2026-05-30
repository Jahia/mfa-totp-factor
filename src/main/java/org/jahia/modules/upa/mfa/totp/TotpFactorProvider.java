package org.jahia.modules.upa.mfa.totp;

import org.apache.commons.lang3.StringUtils;
import org.jahia.modules.upa.mfa.MfaException;
import org.jahia.modules.upa.mfa.MfaFactorProvider;
import org.jahia.modules.upa.mfa.PreparationContext;
import org.jahia.modules.upa.mfa.VerificationContext;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jcr.RepositoryException;
import java.io.Serializable;
import java.util.List;
import java.util.Optional;

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

    @Reference
    public void setTotpService(TotpService totpService) { this.totpService = totpService; }

    @Reference
    public void setUserStore(TotpUserStore userStore) { this.userStore = userStore; }

    @Reference
    public void setBackupCodes(BackupCodes backupCodes) { this.backupCodes = backupCodes; }

    @Reference
    public void setSiteSettingsStore(TotpSiteSettingsStore siteSettingsStore) { this.siteSettingsStore = siteSettingsStore; }

    @Override
    public String getFactorType() {
        return FACTOR_TYPE;
    }

    @Override
    public Serializable prepare(PreparationContext preparationContext) throws MfaException {
        String userId = preparationContext.getSessionContext().getUserId();
        String siteKey = preparationContext.getSessionContext().getSiteKey();

        // Per-site activation / enforcement only applies when there is a real site context.
        // Without one (e.g. a direct GraphQL verify, or a login not tied to a site) the
        // per-site policy is meaningless, so we fall back to the standard behavior:
        // an enrolled user is challenged; an unenrolled user is rejected with not_enrolled.
        // (Crucially, this means we NEVER short-circuit verification when siteKey is absent.)
        if (StringUtils.isNotBlank(siteKey)) {
            TotpSiteSettingsStore.TotpSiteSettings siteSettings;
            try {
                siteSettings = siteSettingsStore.load(siteKey);
            } catch (RepositoryException e) {
                logger.warn("Failed to load TOTP site settings for {}: {}", siteKey, e.getMessage());
                throw new MfaException(ERROR_INTERNAL);
            }

            // Site has TOTP disabled → skip the factor for this session. verify() will
            // accept any submission; the login UI is expected to bypass the step entirely.
            if (!siteSettings.isEnabled()) {
                logger.debug("TOTP skipped for user {} (site '{}' has TOTP disabled)", userId, siteKey);
                return new TotpPreparationResult(true);
            }
            if (!isEnrolled(userId)) {
                // Enabled but the user has not enrolled:
                //   - enforced=true  → block the login; the UI redirects to enrollment.
                //   - enforced=false → skip the factor; the user signs in without TOTP.
                if (siteSettings.isEnforced()) {
                    throw new MfaException(ERROR_ENROLLMENT_REQUIRED, "user", userId);
                }
                logger.debug("TOTP skipped for user {} (not enrolled, site '{}' not enforcing)", userId, siteKey);
                return new TotpPreparationResult(true);
            }
            // Enabled + enrolled → standard flow.
            return new TotpPreparationResult();
        }

        // No site context → original behavior: require an enrolled user.
        if (!isEnrolled(userId)) {
            throw new MfaException(ERROR_NOT_ENROLLED, "user", userId);
        }
        return new TotpPreparationResult();
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

        if (BackupCodes.looksLikeBackupCode(submitted)) {
            return verifyBackupCode(userId, settings.getBackupCodeHashes(), submitted);
        }
        return verifyTotpCode(userId, settings, submitted);
    }

    private boolean verifyTotpCode(String userId, TotpUserStore.TotpUserSettings settings, String submitted) {
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

    private boolean verifyBackupCode(String userId, List<String> hashes, String submitted) {
        Optional<Integer> matchIndex = backupCodes.verifyAndIndex(hashes, submitted);
        if (matchIndex.isPresent()) {
            try {
                userStore.consumeBackupCode(userId, matchIndex.get());
            } catch (RepositoryException e) {
                logger.warn("Failed to consume backup code for user {}: {}", userId, e.getMessage());
                // If we cannot remove the hash, refuse the login — single-use guarantee takes precedence
                return false;
            }
            return true;
        }
        logger.warn("Backup code verification failed for user {}", userId);
        return false;
    }
}
