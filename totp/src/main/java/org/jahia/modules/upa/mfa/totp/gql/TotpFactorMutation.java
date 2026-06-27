package org.jahia.modules.upa.mfa.totp.gql;

import graphql.annotations.annotationTypes.GraphQLDescription;
import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;
import graphql.annotations.annotationTypes.GraphQLNonNull;
import graphql.schema.DataFetchingEnvironment;
import org.apache.commons.lang3.StringUtils;
import org.jahia.modules.graphql.provider.dxm.DataFetchingException;
import org.jahia.modules.graphql.provider.dxm.osgi.annotations.GraphQLOsgiService;
import org.jahia.modules.graphql.provider.dxm.util.ContextUtil;
import org.jahia.modules.upa.mfa.MfaService;
import org.jahia.modules.upa.mfa.MfaSession;
import org.jahia.modules.upa.mfa.MfaFactorState;
import org.jahia.modules.upa.mfa.extensions.BackupCodes;
import org.jahia.modules.upa.mfa.extensions.MfaFactorDirectory;
import org.jahia.modules.upa.mfa.extensions.MfaForeignFactorDrain;
import org.jahia.modules.upa.mfa.extensions.MfaGlobalPolicy;
import org.jahia.modules.upa.mfa.extensions.MfaGraphqlAuth;
import org.jahia.modules.upa.mfa.extensions.MfaPreAuthGuard;
import org.jahia.modules.upa.mfa.extensions.MfaUrls;
import org.jahia.modules.upa.mfa.gql.Result;
import org.jahia.modules.upa.mfa.totp.TotpAuditLog;
import org.jahia.modules.upa.mfa.totp.TotpEnrollmentState;
import org.jahia.modules.upa.mfa.totp.TotpManagementRateLimiter;
import org.jahia.modules.upa.mfa.totp.TotpPreparationResult;
import org.jahia.modules.upa.mfa.totp.TotpService;
import org.jahia.modules.upa.mfa.totp.TotpSiteSettingsStore;
import org.jahia.modules.upa.mfa.totp.TotpUserStore;
import org.jahia.services.usermanager.JahiaUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.jcr.RepositoryException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import static org.jahia.modules.upa.mfa.totp.TotpFactorProvider.FACTOR_TYPE;

/**
 * GraphQL mutation surface for the TOTP factor:
 * {@code enroll / confirmEnroll / prepare / verify / regenerateBackupCodes / disable}.
 * <p>
 * {@code prepare} and {@code verify} go through {@link MfaService} (so the standard
 * rate-limiting / lockout in {@code MfaServiceImpl} applies). The management ops are
 * gated by the caller being an authenticated JCR user, by an in-memory
 * {@link TotpManagementRateLimiter} (defense against online brute force of the management
 * surface), and — where they accept a code — by persisting the matched counter in the same
 * call so the same code cannot be replayed against {@code verify}.
 */
@GraphQLName("MfaTotpFactorMutation")
@GraphQLDescription("Mutations for the TOTP MFA factor")
public class TotpFactorMutation {

    private static final Logger logger = LoggerFactory.getLogger(TotpFactorMutation.class);

    private static final String ERROR_PREFIX = "factor.totp.";
    private static final String ERROR_NOT_AUTHENTICATED = "factor.totp.not_authenticated";
    private static final String ERROR_ALREADY_ENROLLED = "factor.totp.already_enrolled";
    private static final String ERROR_NOT_ENROLLED = "factor.totp.not_enrolled";
    private static final String ERROR_INVALID_CODE = "factor.totp.invalid_code";
    private static final String ERROR_INTERNAL = "factor.totp.internal_error";
    private static final String ERROR_LOCKED_OUT = "factor.totp.locked_out";
    private static final String ERROR_FORCE_NOT_ALLOWED = "factor.totp.force_not_allowed";
    private static final String ERROR_INVALID_URL = "factor.totp.invalid_url";
    private static final String OUTCOME_SUCCESS = "success";

    /** HTTP session attribute used to persist self-service enrollment state when no MFA session exists. */
    private static final String SELF_SERVICE_STATE_ATTR = "upa.mfa.totp.selfService.enrollState";

    private MfaService mfaService;
    private TotpService totpService;
    private TotpUserStore userStore;
    private BackupCodes backupCodes;
    private TotpManagementRateLimiter rateLimiter;
    private TotpSiteSettingsStore siteSettingsStore;
    private TotpAuditLog auditLog;
    private MfaGlobalPolicy globalPolicy;
    private MfaFactorDirectory factorDirectory;
    private MfaForeignFactorDrain foreignFactorDrain;

    @Inject
    @GraphQLOsgiService
    public void setMfaService(MfaService mfaService) {
        this.mfaService = mfaService;
    }

    @Inject
    @GraphQLOsgiService
    public void setForeignFactorDrain(MfaForeignFactorDrain foreignFactorDrain) {
        this.foreignFactorDrain = foreignFactorDrain;
    }

    @Inject
    @GraphQLOsgiService
    public void setGlobalPolicy(MfaGlobalPolicy globalPolicy) {
        this.globalPolicy = globalPolicy;
    }

    @Inject
    @GraphQLOsgiService
    public void setFactorDirectory(MfaFactorDirectory factorDirectory) {
        this.factorDirectory = factorDirectory;
    }

    @Inject
    @GraphQLOsgiService
    public void setTotpService(TotpService totpService) {
        this.totpService = totpService;
    }

    @Inject
    @GraphQLOsgiService
    public void setUserStore(TotpUserStore userStore) {
        this.userStore = userStore;
    }

    @Inject
    @GraphQLOsgiService
    public void setBackupCodes(BackupCodes backupCodes) {
        this.backupCodes = backupCodes;
    }

    @Inject
    @GraphQLOsgiService
    public void setRateLimiter(TotpManagementRateLimiter rateLimiter) {
        this.rateLimiter = rateLimiter;
    }

    @Inject
    @GraphQLOsgiService
    public void setSiteSettingsStore(TotpSiteSettingsStore siteSettingsStore) {
        this.siteSettingsStore = siteSettingsStore;
    }

    @Inject
    @GraphQLOsgiService
    public void setAuditLog(TotpAuditLog auditLog) {
        this.auditLog = auditLog;
    }

    @GraphQLField
    @GraphQLName("enroll")
    @GraphQLDescription("Start TOTP enrollment: generate a fresh secret. Idempotent within a session. "
            + "If the user is already enrolled, force=true is required AND the caller must either be "
            + "an admin (root) OR supply currentCode = a currently-valid TOTP for the existing secret.")
    public TotpEnrollResult enroll(
            @GraphQLName("force") Boolean force,
            @GraphQLName("currentCode") String currentCode,
            DataFetchingEnvironment environment) {

        boolean forceFlag = Boolean.TRUE.equals(force);
        HttpServletRequest request = ContextUtil.getHttpServletRequest(environment.getGraphQlContext());
        HttpServletResponse response = ContextUtil.getHttpServletResponse(environment.getGraphQlContext());

        JahiaUser user = currentNonGuestUser();
        boolean preAuth = (user == null);
        String userId;
        if (preAuth) {
            // Inline enrollment during sign-in: the caller proved the password (initiated MFA
            // session) but is not authenticated yet. Force-re-enrollment is never allowed here.
            if (forceFlag) {
                throw new DataFetchingException(ERROR_FORCE_NOT_ALLOWED);
            }
            userId = requirePreAuthEnrollmentSubject(request);
        } else {
            userId = user.getName();
        }

        TotpUserStore.TotpUserSettings settings;
        try {
            settings = userStore.load(userId);
        } catch (RepositoryException e) {
            logger.warn("Failed to load TOTP settings for user {}: {}", userId, e.getMessage());
            throw new DataFetchingException(ERROR_INTERNAL);
        }
        if (settings.isEnrolled()) {
            // Defense in depth: the pre-auth guard already refuses users owning any enforced
            // factor, so an enrolled user can only reach re-enrollment authenticated.
            if (preAuth) {
                throw new DataFetchingException(ERROR_NOT_AUTHENTICATED);
            }
            authorizeReEnroll(user, userId, forceFlag, currentCode);
        }

        MfaSession storedSession = mfaService.getMfaSession(request);
        // Outside of a login flow (e.g. self-service enrollment from settings) there is no MFA
        // session; we persist the transient enrollment state directly on the HTTP session so
        // confirmEnroll can retrieve it. We still call prepareFactor to obtain a session DTO
        // for the response payload — that returned object exposes a stub session with the
        // ERROR_NO_SESSION marker, which clients can ignore for self-service flows.
        boolean selfService = (storedSession == null);
        MfaSession responseSession = selfService
                ? mfaService.prepareFactor(FACTOR_TYPE, request, response)
                : storedSession;
        // For reads/writes of the transient enrollment state, only use the stored MfaSession
        // when one exists server-side; otherwise we go through the HTTP session attribute.
        MfaSession stateSession = selfService ? null : storedSession;

        // Reuse an already-generated transient secret if enroll() is called twice in a row.
        // Honour the short TTL: if the previous state has expired, regenerate a fresh secret.
        TotpEnrollmentState existing = readEnrollmentState(stateSession, request);
        String secretBase32;
        if (existing != null && !existing.isExpired()) {
            secretBase32 = existing.getSecretBase32();
        } else {
            byte[] raw = totpService.generateSecret();
            secretBase32 = totpService.toBase32(raw);
            writeEnrollmentState(stateSession, request, new TotpEnrollmentState(secretBase32));
        }

        String issuer = resolveIssuer(responseSession);
        String accountName = userId;
        String otpauthUri = totpService.buildOtpauthUri(issuer, accountName, secretBase32);

        logger.info("TOTP enrollment initiated for user {} (force={}, selfService={})", userId, forceFlag, selfService);
        return new TotpEnrollResult(responseSession, secretBase32, otpauthUri, issuer, accountName);
    }

    /**
     * Read the transient enrollment state, preferring the MfaSession (login flow) and falling
     * back to the HTTP session attribute (self-service enrollment).
     */
    private TotpEnrollmentState readEnrollmentState(MfaSession session, HttpServletRequest request) {
        if (session != null) {
            Object existing = session.getOrCreateFactorState(FACTOR_TYPE).getPreparationResult();
            if (existing instanceof TotpEnrollmentState) {
                return (TotpEnrollmentState) existing;
            }
            return null;
        }
        HttpSession http = request.getSession(false);
        if (http == null) {
            return null;
        }
        Object existing = http.getAttribute(SELF_SERVICE_STATE_ATTR);
        return (existing instanceof TotpEnrollmentState) ? (TotpEnrollmentState) existing : null;
    }

    /**
     * Write the transient enrollment state, preferring the MfaSession (login flow) and falling
     * back to the HTTP session attribute (self-service enrollment). A {@code null} state
     * clears the slot.
     */
    private void writeEnrollmentState(MfaSession session, HttpServletRequest request, TotpEnrollmentState state) {
        if (session != null) {
            session.getOrCreateFactorState(FACTOR_TYPE).setPreparationResult(state);
            return;
        }
        HttpSession http = request.getSession(state != null);
        if (http == null) {
            return;
        }
        if (state == null) {
            http.removeAttribute(SELF_SERVICE_STATE_ATTR);
        } else {
            http.setAttribute(SELF_SERVICE_STATE_ATTR, state);
        }
    }

    /**
     * The pre-authentication inline-enrollment guard. Delegates to the shared
     * {@link MfaPreAuthGuard#requireEnrollmentSubject} (the anti-takeover barrier: a caller who
     * only proved the password must never add a factor to an account that already owns one).
     *
     * @return the MFA-session user id (the enrollment subject)
     */
    private String requirePreAuthEnrollmentSubject(HttpServletRequest request) {
        return MfaPreAuthGuard.requireEnrollmentSubject(request, FACTOR_TYPE, ERROR_PREFIX,
                mfaService, globalPolicy, factorDirectory);
    }

    @GraphQLField
    @GraphQLName("confirmEnroll")
    @GraphQLDescription("Finalize TOTP enrollment with the first generated code. Returns one-shot backup codes.")
    public TotpConfirmEnrollResult confirmEnroll(
            @GraphQLName("code") @GraphQLNonNull String code,
            DataFetchingEnvironment environment) {

        if (!isAcceptableCodeLength(code)) {
            throw new DataFetchingException(ERROR_INVALID_CODE);
        }
        HttpServletRequest request = ContextUtil.getHttpServletRequest(environment.getGraphQlContext());
        HttpServletResponse response = ContextUtil.getHttpServletResponse(environment.getGraphQlContext());

        JahiaUser user = currentNonGuestUser();
        boolean preAuth = (user == null);
        String userId = preAuth ? requirePreAuthEnrollmentSubject(request) : user.getName();

        if (rateLimiter.isLockedOut(userId)) {
            throw new DataFetchingException(ERROR_LOCKED_OUT);
        }

        MfaSession session = mfaService.getMfaSession(request);
        // The enrollment state may live on the MfaSession (login-flow enrollment) or on the
        // HTTP session (self-service enrollment from settings). Read whichever applies.
        TotpEnrollmentState state = readEnrollmentState(session, request);
        if (state == null) {
            // No transient enrollment state means the submitted code cannot be matched against
            // any enrollment secret — surface as invalid_code, consistent with the spec.
            logger.debug("confirmEnroll called with no transient enrollment state for user {}", userId);
            rateLimiter.recordFailure(userId);
            throw new DataFetchingException(ERROR_INVALID_CODE);
        }
        if (state.isExpired()) {
            // Discard the expired secret immediately and treat as invalid_code.
            writeEnrollmentState(session, request, null);
            logger.debug("confirmEnroll called with an expired enrollment state for user {}", userId);
            rateLimiter.recordFailure(userId);
            throw new DataFetchingException(ERROR_INVALID_CODE);
        }
        String secretBase32 = state.getSecretBase32();

        byte[] secret = totpService.fromBase32(secretBase32);
        long now = System.currentTimeMillis() / 1000L;
        Optional<Long> matched = totpService.verifyCode(secret, code, now, -1L, TotpService.DRIFT_WINDOWS);
        if (!matched.isPresent()) {
            rateLimiter.recordFailure(userId);
            throw new DataFetchingException(ERROR_INVALID_CODE);
        }

        if (preAuth) {
            return finalizePreAuthEnrollment(userId, secretBase32, code, session, request, response);
        }

        List<String> plaintextBackup = backupCodes.generate();
        List<String> hashed = plaintextBackup.stream().map(backupCodes::hash).collect(Collectors.toList());

        try {
            // SINGLE JCR transaction: persists the secret, enrolled flag, hashed backup codes
            // AND the matched counter so the enrollment code cannot be replayed at login.
            userStore.saveEnrollment(userId, secretBase32, hashed, matched.orElseThrow(() ->
                    new DataFetchingException(ERROR_INVALID_CODE)));
            // Enrollment satisfied — clear any running grace window.
            userStore.clearGrace(userId);
        } catch (RepositoryException e) {
            logger.warn("Failed to persist TOTP enrollment for user {}: {}", userId, e.getMessage());
            throw new DataFetchingException(ERROR_INTERNAL);
        }

        // Wipe the transient secret from wherever it was stored.
        writeEnrollmentState(session, request, null);
        if (session != null) {
            session.getOrCreateFactorState(FACTOR_TYPE).setPrepared(false);
        }
        rateLimiter.recordSuccess(userId);

        MfaSession responseSession = (session != null) ? session : mfaService.createNoSessionError();
        auditLog.recordEvent("confirmEnroll", OUTCOME_SUCCESS, userId, auditSiteKey(responseSession), null);
        logger.info("TOTP enrollment confirmed for user {}", userId);
        return new TotpConfirmEnrollResult(responseSession, plaintextBackup);
    }

    /**
     * Finalize an inline (pre-authentication) enrollment and complete the login in one step.
     * <p>
     * The enrollment is persisted with {@code lastUsedCounter = -1} — the matched counter is
     * deliberately NOT consumed here — and the submitted code is then handed to the standard
     * {@code verifyFactor} chokepoint, which re-verifies it, consumes the counter atomically
     * (replay protection), marks the factor verified and, once every required factor is done,
     * authenticates the user. The not-yet-consumed window is confined to this single request and
     * the guard guarantees a brand-new enrollment (no prior counter exists), so the
     * "consume via the chokepoint" invariant is preserved rather than bypassed.
     */
    private TotpConfirmEnrollResult finalizePreAuthEnrollment(String userId, String secretBase32, String code,
                                                              MfaSession session, HttpServletRequest request,
                                                              HttpServletResponse response) {
        List<String> plaintextBackup = backupCodes.generate();
        List<String> hashed = plaintextBackup.stream().map(backupCodes::hash).collect(Collectors.toList());
        try {
            userStore.saveEnrollment(userId, secretBase32, hashed, -1L);
            userStore.clearGrace(userId);
        } catch (RepositoryException e) {
            logger.warn("Failed to persist TOTP inline enrollment for user {}: {}", userId, e.getMessage());
            throw new DataFetchingException(ERROR_INTERNAL);
        }
        // Wipe the transient secret and hand the factor to the standard verify path with a real
        // (non-skipped) preparation marker.
        writeEnrollmentState(session, request, null);
        MfaFactorState factorState = session.getOrCreateFactorState(FACTOR_TYPE);
        factorState.setPreparationResult(new TotpPreparationResult());
        factorState.setPrepared(true);
        // Through the drain wrapper: a genuine verification must also release any FOREIGN
        // enforced factor (e.g. UPA's email_code) that cannot skip itself.
        MfaSession verifiedSession = foreignFactorDrain.verifyFactor(FACTOR_TYPE, code, request, response);
        rateLimiter.recordSuccess(userId);
        auditLog.recordEvent("confirmEnroll", OUTCOME_SUCCESS, userId, auditSiteKey(verifiedSession), "inlineLogin");
        logger.info("TOTP inline enrollment confirmed during sign-in for user {}", userId);
        return new TotpConfirmEnrollResult(verifiedSession, plaintextBackup);
    }

    @GraphQLField
    @GraphQLName("prepare")
    @GraphQLDescription("No-op preparation; marks the factor 'prepared' in the MFA session.")
    public TotpPreparation prepare(DataFetchingEnvironment environment) {
        HttpServletRequest request = ContextUtil.getHttpServletRequest(environment.getGraphQlContext());
        HttpServletResponse response = ContextUtil.getHttpServletResponse(environment.getGraphQlContext());
        MfaSession session = mfaService.prepareFactor(FACTOR_TYPE, request, response);
        Object prep = session.getOrCreateFactorState(FACTOR_TYPE).getPreparationResult();
        boolean skipped = prep instanceof TotpPreparationResult && ((TotpPreparationResult) prep).isSkipped();
        return new TotpPreparation(session, skipped);
    }

    @GraphQLField
    @GraphQLName("verify")
    @GraphQLDescription("Verify a TOTP code or a backup code. Subject to UPA rate limiting.")
    public Result verify(
            @GraphQLName("code") @GraphQLNonNull String code,
            DataFetchingEnvironment environment) {
        HttpServletRequest request = ContextUtil.getHttpServletRequest(environment.getGraphQlContext());
        if (!isAcceptableCodeLength(code) && !isPreparationSkipped(request)) {
            throw new DataFetchingException(ERROR_INVALID_CODE);
        }
        HttpServletResponse response = ContextUtil.getHttpServletResponse(environment.getGraphQlContext());
        // Through the drain wrapper: a genuine verification must also release any FOREIGN
        // enforced factor (e.g. UPA's email_code) that cannot skip itself.
        MfaSession session = foreignFactorDrain.verifyFactor(FACTOR_TYPE, code, request, response);
        return new Result(session);
    }

    /**
     * The pick-one drain submits an EMPTY code for a preparation the provider marked skipped
     * (enforcement satisfied by another factor, site disabled, …). Let it through to the
     * standard verify path — {@code TotpFactorProvider.verify} accepts a skipped preparation
     * without consuming a rate-limit attempt. Everything else keeps failing fast on length,
     * shielding the rate limiter from garbage submissions.
     */
    private boolean isPreparationSkipped(HttpServletRequest request) {
        MfaSession session = mfaService.getMfaSession(request);
        if (session == null) {
            return false;
        }
        Object prep = session.getOrCreateFactorState(FACTOR_TYPE).getPreparationResult();
        return prep instanceof TotpPreparationResult && ((TotpPreparationResult) prep).isSkipped();
    }

    @GraphQLField
    @GraphQLName("regenerateBackupCodes")
    @GraphQLDescription("Regenerate the backup-code set. Requires a valid current TOTP code.")
    public TotpBackupCodesResult regenerateBackupCodes(
            @GraphQLName("code") @GraphQLNonNull String code,
            DataFetchingEnvironment environment) {
        HttpServletRequest request = ContextUtil.getHttpServletRequest(environment.getGraphQlContext());
        String userId = consumeSelfServiceCode(code);

        List<String> plaintext = backupCodes.generate();
        List<String> hashed = new ArrayList<>(plaintext.size());
        for (String c : plaintext) {
            hashed.add(backupCodes.hash(c));
        }
        try {
            userStore.replaceBackupCodes(userId, hashed);
        } catch (RepositoryException e) {
            throw new DataFetchingException(ERROR_INTERNAL);
        }
        rateLimiter.recordSuccess(userId);
        MfaSession session = mfaService.getMfaSession(request);
        auditLog.recordEvent("regenerateBackupCodes", OUTCOME_SUCCESS, userId, auditSiteKey(session), null);
        logger.info("Backup codes regenerated for user {}", userId);
        return new TotpBackupCodesResult(session, plaintext);
    }

    @GraphQLField
    @GraphQLName("disable")
    @GraphQLDescription("Disable TOTP for the current user. Requires a valid current TOTP code.")
    public Result disable(
            @GraphQLName("code") @GraphQLNonNull String code,
            DataFetchingEnvironment environment) {
        HttpServletRequest request = ContextUtil.getHttpServletRequest(environment.getGraphQlContext());
        String userId = consumeSelfServiceCode(code);

        try {
            userStore.disable(userId);
        } catch (RepositoryException e) {
            throw new DataFetchingException(ERROR_INTERNAL);
        }
        rateLimiter.recordSuccess(userId);
        // In self-service flows there is no MFA session; fall back to the no-session marker so
        // clients selecting session.* fields don't NPE on a null mfaSession.
        MfaSession session = mfaService.getMfaSession(request);
        if (session == null) {
            session = mfaService.createNoSessionError();
        }
        auditLog.recordEvent("disable", OUTCOME_SUCCESS, userId, auditSiteKey(session), null);
        logger.info("TOTP disabled for user {}", userId);
        return new Result(session);
    }

    /**
     * Shared front of the self-service management mutations that mutate an existing enrollment
     * ({@code regenerateBackupCodes} / {@code disable}): require an authenticated, enrolled, not
     * rate-limited caller, then verify-and-CONSUME the submitted current code through the
     * replay-protection chokepoint. On a code miss it records a failure and throws
     * {@code invalid_code}; on success the caller is responsible for the {@code recordSuccess}
     * after its own write succeeds (so a failed write does not clear the lockout window).
     *
     * @return the authenticated user id (after a successful code consumption)
     */
    private String consumeSelfServiceCode(String code) {
        if (!isAcceptableCodeLength(code)) {
            throw new DataFetchingException(ERROR_INVALID_CODE);
        }
        JahiaUser user = currentNonGuestUser();
        if (user == null) {
            throw new DataFetchingException(ERROR_NOT_AUTHENTICATED);
        }
        String userId = user.getName();
        if (rateLimiter.isLockedOut(userId)) {
            throw new DataFetchingException(ERROR_LOCKED_OUT);
        }
        TotpUserStore.TotpUserSettings settings;
        try {
            settings = userStore.load(userId);
        } catch (RepositoryException e) {
            throw new DataFetchingException(ERROR_INTERNAL);
        }
        if (!settings.isEnrolled()) {
            throw new DataFetchingException(ERROR_NOT_ENROLLED);
        }
        Long matched = verifyTotpAndConsume(userId, code);
        if (matched == null) {
            rateLimiter.recordFailure(userId);
            throw new DataFetchingException(ERROR_INVALID_CODE);
        }
        return userId;
    }

    private void authorizeReEnroll(JahiaUser user, String userId, boolean forceFlag, String currentCode) {
        if (!forceFlag) {
            throw new DataFetchingException(ERROR_ALREADY_ENROLLED);
        }
        // force=true is dangerous (it rotates the second factor). Require admin OR a valid
        // current TOTP code for the existing secret.
        if (user.isRoot()) {
            return;
        }
        if (StringUtils.isBlank(currentCode)) {
            logger.warn("Refused enroll(force=true) for user {}: no currentCode and not admin", userId);
            throw new DataFetchingException(ERROR_FORCE_NOT_ALLOWED);
        }
        if (rateLimiter.isLockedOut(userId)) {
            logger.warn("Refused enroll(force=true) for user {}: rate-limited", userId);
            throw new DataFetchingException(ERROR_LOCKED_OUT);
        }
        Long matched = verifyTotpAndConsume(userId, currentCode);
        if (matched == null) {
            rateLimiter.recordFailure(userId);
            logger.warn("Refused enroll(force=true) for user {}: invalid currentCode", userId);
            throw new DataFetchingException(ERROR_INVALID_CODE);
        }
        rateLimiter.recordSuccess(userId);
    }

    /**
     * Verify a submitted TOTP code and, on success, atomically consume the matched counter so the
     * same code cannot be replayed (against {@code verify} or any other management mutation). It
     * delegates to {@link TotpUserStore#verifyAndConsumeTotp} — the single replay-protection
     * chokepoint that re-reads, verifies and persists the consumed counter in one JCR transaction;
     * it does NOT call {@code updateLastUsedCounter}.
     *
     * @return the matched counter on success ({@code Optional<Long>.orElse(null)}), or {@code null}
     *         on failure / invalid input.
     */
    private Long verifyTotpAndConsume(String userId, String code) {
        if (!isAcceptableCodeLength(code)) {
            return null;
        }
        // The chokepoint re-reads the freshest lastUsedCounter from JCR inside the same
        // transaction that persists the consumed counter, eliminating the read-modify-write
        // race that previously allowed replay — so no pre-loaded settings are needed here.
        long now = System.currentTimeMillis() / 1000L;
        try {
            Optional<Long> matched = userStore.verifyAndConsumeTotp(userId, totpService, code.trim(),
                    now, TotpService.DRIFT_WINDOWS);
            return matched.orElse(null);
        } catch (RepositoryException e) {
            logger.warn("Failed to persist consumed counter for user {}: {}", userId, e.getMessage());
            return null;
        }
    }

    @GraphQLField
    @GraphQLName("setSiteSettings")
    @GraphQLDescription("Set the per-site TOTP policy (enabled / enabledGroups) and the optional per-site "
            + "login/logout URLs. URLs must be server-relative paths starting with '/' (open-redirect "
            + "guard). Enforcement is global (org.jahia.modules.mfa.extensions). Caller must be a site "
            + "administrator on the target site.")
    public TotpSiteSettingsResult setSiteSettings(
            @GraphQLName("siteKey") @GraphQLNonNull String siteKey,
            @GraphQLName("enabled") @GraphQLNonNull Boolean enabled,
            @GraphQLName("enabledGroups") List<String> enabledGroups,
            @GraphQLName("loginUrl") String loginUrl,
            @GraphQLName("logoutUrl") String logoutUrl) {

        if (StringUtils.isBlank(siteKey)) {
            throw new DataFetchingException("siteKey must not be blank");
        }
        // Authorization gate (site admin). No JCR write anymore - persistence is the per-site .cfg.
        TotpAdminAccess.requireSiteAdmin(siteKey);
        // The login/logout URLs are factor-agnostic and shared in the per-site .cfg, and each is
        // tracked INDEPENDENTLY: "omitted" (arg == null -> keep the stored URL) is distinguished from
        // "explicit clear" (arg == "" -> store null) per field, BEFORE validation collapses both to
        // null. Tracking the two fields separately means an omitted field never erases its sibling
        // (the data-loss fix); the store keeps the current stored value for any field not provided.
        boolean loginUrlProvided = (loginUrl != null);
        boolean logoutUrlProvided = (logoutUrl != null);
        // Open-redirect guard: only server-relative paths may be stored. Validate here (clear,
        // field-specific error for the UI) on top of the enforcement inside the store itself. Only
        // validate a field that was actually provided. validateSiteRelativeUrl("") returns null,
        // which is the correct "clear" value.
        String cleanLoginUrl;
        String cleanLogoutUrl;
        try {
            cleanLoginUrl = loginUrlProvided ? MfaUrls.validateSiteRelativeUrl(loginUrl) : null;
            cleanLogoutUrl = logoutUrlProvided ? MfaUrls.validateSiteRelativeUrl(logoutUrl) : null;
        } catch (IllegalArgumentException e) {
            logger.warn("Rejected TOTP site settings for {}: invalid login/logout URL submitted by {}",
                    siteKey, currentUserName());
            throw new DataFetchingException(ERROR_INVALID_URL);
        }
        try {
            siteSettingsStore.save(siteKey, new TotpSiteSettingsStore.TotpSiteSettings(
                    enabled, enabledGroups, cleanLoginUrl, cleanLogoutUrl, loginUrlProvided, logoutUrlProvided));
            // Report the URLs that are actually in effect after the write: the submitted values
            // when provided, otherwise the ones that survived the partial update.
            TotpSiteSettingsStore.TotpSiteSettings effective = siteSettingsStore.load(siteKey);
            auditLog.recordEvent("setSiteSettings", OUTCOME_SUCCESS, currentUserName(), siteKey,
                    "enabled=" + enabled
                            + ", loginUrl=" + StringUtils.defaultString(effective.getLoginUrl())
                            + ", logoutUrl=" + StringUtils.defaultString(effective.getLogoutUrl()));
            return new TotpSiteSettingsResult(siteKey, enabled, enabledGroups,
                    effective.getLoginUrl(), effective.getLogoutUrl());
        } catch (IOException e) {
            logger.warn("Failed to save TOTP site settings for {}: {}", siteKey, e.getMessage());
            throw new DataFetchingException(ERROR_INTERNAL);
        }
    }

    @GraphQLField
    @GraphQLName("resetUserMfa")
    @GraphQLDescription("Admin recovery: clear a user's TOTP enrollment (secret + backup codes) WITHOUT "
            + "requiring their code, for users who lost their device and backup codes. Caller must be a "
            + "site administrator on the given site.")
    public boolean resetUserMfa(
            @GraphQLName("userId") @GraphQLNonNull String userId,
            @GraphQLName("siteKey") @GraphQLNonNull String siteKey) {

        if (StringUtils.isBlank(userId)) {
            throw new DataFetchingException("userId must not be blank");
        }
        TotpAdminAccess.requireSiteAdmin(siteKey);
        String admin = currentUserName();
        try {
            userStore.disable(userId);
            userStore.clearGrace(userId);
            rateLimiter.recordSuccess(userId); // clear any lockout state too
            auditLog.recordEvent("reset", OUTCOME_SUCCESS, userId, siteKey, "by=" + admin);
            logger.info("TOTP enrollment reset for user {} by admin {}", userId, admin);
            return true;
        } catch (RepositoryException e) {
            logger.warn("Failed to reset TOTP for user {}: {}", userId, e.getMessage());
            throw new DataFetchingException(ERROR_INTERNAL);
        }
    }

    private static String currentUserName() {
        return MfaGraphqlAuth.currentUserName();
    }

    private static JahiaUser currentNonGuestUser() {
        return MfaGraphqlAuth.currentNonGuestUser();
    }

    /** Best-effort site key for auditing a self-service event (empty when outside a site flow). */
    private static String auditSiteKey(MfaSession session) {
        if (session != null && session.getContext() != null
                && StringUtils.isNotBlank(session.getContext().getSiteKey())) {
            return session.getContext().getSiteKey();
        }
        return "";
    }

    private static boolean isAcceptableCodeLength(String code) {
        if (StringUtils.isBlank(code)) {
            return false;
        }
        return code.length() <= TotpService.MAX_CODE_LENGTH;
    }

    private static String resolveIssuer(MfaSession session) {
        if (session != null && session.getContext() != null
                && StringUtils.isNotBlank(session.getContext().getSiteKey())) {
            return session.getContext().getSiteKey();
        }
        return "Jahia";
    }
}
