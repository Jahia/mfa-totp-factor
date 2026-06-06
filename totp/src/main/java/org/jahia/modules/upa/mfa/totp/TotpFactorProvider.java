package org.jahia.modules.upa.mfa.totp;

import org.apache.commons.lang3.StringUtils;
import org.jahia.modules.upa.mfa.MfaException;
import org.jahia.modules.upa.mfa.MfaFactorProvider;
import org.jahia.modules.upa.mfa.MfaService;
import org.jahia.modules.upa.mfa.MfaSession;
import org.jahia.modules.upa.mfa.PreparationContext;
import org.jahia.modules.upa.mfa.VerificationContext;
import org.jahia.modules.upa.mfa.extensions.BackupCodes;
import org.jahia.modules.upa.mfa.extensions.MfaGlobalPolicy;
import org.jahia.modules.upa.mfa.extensions.MfaSiteProvider;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jcr.RepositoryException;
import javax.servlet.http.HttpServletRequest;
import java.io.Serializable;
import java.util.ArrayList;
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
            return prepareForSite(preparationContext, userId, siteKey);
        }

        // No site context → original behavior: require an enrolled user.
        if (!isEnrolled(userId)) {
            throw new MfaException(ERROR_NOT_ENROLLED, "user", userId);
        }
        return new TotpPreparationResult();
    }

    /**
     * The site-scoped decision once the site has TOTP enabled and the user is in scope.
     * Enforcement is GLOBAL ({@link MfaGlobalPolicy}); a user must satisfy it with AT LEAST ONE
     * of the enforced factors — the others skip:
     * <ul>
     *   <li>not globally enforced → enrolled users are challenged, others skip (opt-in);</li>
     *   <li>enforced and another enforced factor was already verified in this MFA session →
     *       skip (pick-one satisfied);</li>
     *   <li>enforced and the user is enrolled here → challenge;</li>
     *   <li>enforced, not enrolled here, but another enforced factor is configured for the
     *       user → skip (they will verify with that one);</li>
     *   <li>enforced and NO enforced factor configured → global grace window, then block with
     *       {@code enrollment_required} (the login UI offers inline enrollment).</li>
     * </ul>
     */
    private Serializable prepareForSite(PreparationContext preparationContext, String userId, String siteKey)
            throws MfaException {
        boolean enrolled = isEnrolled(userId);
        if (!globalPolicy.isEnforced(FACTOR_TYPE)) {
            if (!enrolled) {
                logger.debug("TOTP skipped for user {} (not enrolled, factor not globally enforced)", userId);
                return new TotpPreparationResult(true);
            }
            return new TotpPreparationResult();
        }
        if (anotherEnforcedFactorVerified(preparationContext)) {
            logger.debug("TOTP skipped for user {} (another enforced factor already verified)", userId);
            return new TotpPreparationResult(true);
        }
        if (enrolled) {
            return new TotpPreparationResult();
        }
        if (anotherEnforcedFactorConfigured(userId)) {
            logger.debug("TOTP skipped for user {} (another enforced factor is configured)", userId);
            return new TotpPreparationResult(true);
        }
        return prepareNoEnforcedFactor(userId, siteKey);
    }

    /**
     * The user has NONE of the globally enforced factors configured: allow sign-in during the
     * global grace window (per-user start tracked as before), then block with
     * {@code enrollment_required} carrying the factors the user may enroll inline.
     */
    private Serializable prepareNoEnforcedFactor(String userId, String siteKey) throws MfaException {
        long graceDays = globalPolicy.getGraceDays();
        if (graceDays > 0) {
            long now = System.currentTimeMillis();
            long graceStart;
            try {
                graceStart = userStore.getOrStartGraceMillis(userId, now);
            } catch (RepositoryException e) {
                logger.warn("Failed to read TOTP grace state for user {}: {}", userId, e.getMessage());
                throw new MfaException(ERROR_INTERNAL);
            }
            if ((now - graceStart) < graceDays * 24L * 60L * 60L * 1000L) {
                logger.debug("Enrollment grace still active for user {} (started {}, {} days)",
                        userId, graceStart, graceDays);
                return new TotpPreparationResult(true);
            }
        }
        auditLog.recordEvent("enrollmentRequired", "denied", userId, siteKey,
                graceDays > 0 ? "graceExpired" : "noGrace");
        throw new MfaException(ERROR_ENROLLMENT_REQUIRED, "user", userId,
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
     * {@code MfaSiteProvider}s). A provider that cannot answer fails CLOSED for sign-in:
     * the error propagates and blocks the login rather than silently skipping a factor.
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
