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
    private TotpAuditLog auditLog;

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
            // Per-group scoping: if the site restricts the policy to specific groups and the
            // user is not a member of any of them, the factor does not apply to this user.
            if (!isInScope(userId, siteSettings.getEnabledGroups())) {
                logger.debug("TOTP skipped for user {} (not in any policy group on site '{}')", userId, siteKey);
                return new TotpPreparationResult(true);
            }
            if (!isEnrolled(userId)) {
                return prepareUnenrolled(userId, siteKey, siteSettings);
            }
            // Enabled + in scope + enrolled → standard flow.
            return new TotpPreparationResult();
        }

        // No site context → original behavior: require an enrolled user.
        if (!isEnrolled(userId)) {
            throw new MfaException(ERROR_NOT_ENROLLED, "user", userId);
        }
        return new TotpPreparationResult();
    }

    /**
     * Decide what to do when the site has TOTP enabled (and the user is in scope) but the
     * user has not enrolled:
     * <ul>
     *   <li>not enforced → skip the factor; the user signs in without TOTP;</li>
     *   <li>enforced with no grace ({@code graceDays == 0}) → block immediately;</li>
     *   <li>enforced with a grace window → allow sign-in until the window elapses, after
     *       which the login is blocked and the UI redirects to enrollment.</li>
     * </ul>
     */
    private Serializable prepareUnenrolled(String userId, String siteKey,
                                           TotpSiteSettingsStore.TotpSiteSettings siteSettings)
            throws MfaException {
        if (!siteSettings.isEnforced()) {
            logger.debug("TOTP skipped for user {} (not enrolled, site not enforcing)", userId);
            return new TotpPreparationResult(true);
        }
        long graceDays = siteSettings.getGraceDays();
        if (graceDays <= 0) {
            auditLog.recordEvent("enrollmentRequired", "denied", userId, siteKey, "noGrace");
            throw new MfaException(ERROR_ENROLLMENT_REQUIRED, "user", userId);
        }
        long now = System.currentTimeMillis();
        long graceStart;
        try {
            graceStart = userStore.getOrStartGraceMillis(userId, now);
        } catch (RepositoryException e) {
            logger.warn("Failed to read TOTP grace state for user {}: {}", userId, e.getMessage());
            throw new MfaException(ERROR_INTERNAL);
        }
        long graceMillis = graceDays * 24L * 60L * 60L * 1000L;
        if ((now - graceStart) < graceMillis) {
            logger.debug("TOTP enrollment grace still active for user {} (started {}, {} days)",
                    userId, graceStart, graceDays);
            return new TotpPreparationResult(true);
        }
        auditLog.recordEvent("enrollmentRequired", "denied", userId, siteKey, "graceExpired");
        throw new MfaException(ERROR_ENROLLMENT_REQUIRED, "user", userId);
    }

    private boolean isInScope(String userId, List<String> enabledGroups) throws MfaException {
        try {
            return userStore.isMemberOfAnyGroup(userId, enabledGroups);
        } catch (RepositoryException e) {
            logger.warn("Failed to check group membership for user {}: {}", userId, e.getMessage());
            throw new MfaException(ERROR_INTERNAL);
        }
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

        boolean backupCode = BackupCodes.looksLikeBackupCode(submitted);
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
