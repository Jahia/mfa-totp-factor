package org.jahia.modules.upa.mfa.extensions.gql;

import graphql.annotations.annotationTypes.GraphQLDescription;
import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;
import graphql.annotations.annotationTypes.GraphQLTypeExtension;
import graphql.schema.DataFetchingEnvironment;
import org.apache.commons.lang3.StringUtils;
import org.jahia.modules.graphql.provider.dxm.DXGraphQLProvider;
import org.jahia.modules.graphql.provider.dxm.DataFetchingException;
import org.jahia.modules.graphql.provider.dxm.util.ContextUtil;
import org.jahia.modules.upa.mfa.MfaService;
import org.jahia.modules.upa.mfa.MfaSession;
import org.jahia.modules.upa.mfa.extensions.MfaGlobalPolicy;
import org.jahia.modules.upa.mfa.extensions.MfaResetRequestRateLimiter;
import org.jahia.osgi.BundleUtils;
import org.jahia.registries.ServicesRegistry;
import org.jahia.services.mail.MailService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.List;

/**
 * Adds the top-level {@code mfaRequestReset} mutation for a user who has proven their password but
 * cannot pass the second factor (lost authenticator, no backup codes, no other factor). It notifies
 * the configured administrator(s) by email so they can run the existing admin reset mutations
 * ({@code upa.mfaFactors.totp.resetUserMfa} / {@code webauthn.resetUserWebauthn}) for that user.
 * <p>
 * Security: the subject is derived exclusively from the server-side {@link MfaSession} (password
 * already proven) — there is NO user argument, so this cannot be used to probe or target other
 * accounts (no enumeration, no IDOR). Without an active session it fails with
 * {@code no_active_session} (the affordance is only shown at the MFA step). It is rate-limited per
 * user, returns a generic success regardless of whether an email went out, and never includes any
 * code or secret in the notification.
 */
@GraphQLTypeExtension(DXGraphQLProvider.Mutation.class)
public class MfaResetRequestMutationExtension {

    private static final Logger logger = LoggerFactory.getLogger(MfaResetRequestMutationExtension.class);
    private static final String ERROR_NO_SESSION = "no_active_session";

    private MfaResetRequestMutationExtension() {
        // not instantiated
    }

    @GraphQLField
    @GraphQLName("mfaRequestReset")
    @GraphQLDescription("For a user stuck at the MFA step (password proven, no usable second factor): "
            + "notify the configured administrators by email to request an MFA reset. Operates only on "
            + "the active sign-in session (no user argument) and always returns true.")
    public static boolean mfaRequestReset(DataFetchingEnvironment environment) {
        HttpServletRequest request = ContextUtil.getHttpServletRequest(environment.getGraphQlContext());
        MfaService mfaService = BundleUtils.getOsgiService(MfaService.class, null);
        MfaSession session = (mfaService == null || request == null) ? null : mfaService.getMfaSession(request);
        if (session == null || session.getContext() == null) {
            // The UI only calls this at the MFA step; outside any session there is nothing to act on.
            throw new DataFetchingException(ERROR_NO_SESSION);
        }

        String userId = session.getContext().getUserId();
        String siteKey = session.getContext().getSiteKey();

        MfaResetRequestRateLimiter limiter = BundleUtils.getOsgiService(MfaResetRequestRateLimiter.class, null);
        if (limiter != null && !limiter.tryAcquire(userId)) {
            // Within the window: do not re-notify, but do not reveal the throttle either.
            logger.info("MFA reset request throttled (user={}, site={})", userId, siteKey);
            return true;
        }

        notifyAdministrators(userId, siteKey);
        return true;
    }

    /** Best-effort: email the configured recipients. Absence of recipients/mail is logged, not surfaced. */
    private static void notifyAdministrators(String userId, String siteKey) {
        MfaGlobalPolicy policy = BundleUtils.getOsgiService(MfaGlobalPolicy.class, null);
        List<String> recipients = policy == null ? List.of() : policy.getResetNotifyEmails();
        if (recipients.isEmpty()) {
            logger.warn("MFA reset requested (user={}, site={}) but resetRequest.notifyEmail is not "
                    + "configured - no administrator was notified", userId, siteKey);
            return;
        }

        String subject = "[MFA] Reset requested for user " + userId
                + (StringUtils.isNotBlank(siteKey) ? " on site " + siteKey : "");
        String body = buildBody(userId, siteKey);

        MailService mailService = ServicesRegistry.getInstance().getMailService();
        boolean sent = mailService != null
                && mailService.sendHtmlMessage(null, String.join(",", recipients), null, null, subject, body);
        if (sent) {
            logger.info("MFA reset request notification sent to {} recipient(s) (user={}, site={})",
                    recipients.size(), userId, siteKey);
        } else {
            logger.warn("MFA reset request notification could NOT be sent (mail service unavailable or "
                    + "send failed) for user={}, site={}", userId, siteKey);
        }
    }

    private static String buildBody(String userId, String siteKey) {
        // Plain, code-free admin notification. No secrets, no tokens.
        return "<p>A user has requested a multi-factor authentication (MFA) reset because they can no "
                + "longer pass their second factor.</p>"
                + "<ul>"
                + "<li><strong>User:</strong> " + escape(userId) + "</li>"
                + "<li><strong>Site:</strong> " + escape(StringUtils.defaultIfBlank(siteKey, "(none)")) + "</li>"
                + "<li><strong>Requested at:</strong> " + Instant.now() + "</li>"
                + "</ul>"
                + "<p>After verifying the request through your usual identity-check process, reset the "
                + "user's factor(s) with the admin GraphQL mutations "
                + "<code>upa.mfaFactors.totp.resetUserMfa(userId, siteKey)</code> and/or "
                + "<code>upa.mfaFactors.webauthn.resetUserWebauthn(userId, siteKey)</code>. The user can "
                + "then enrol again at their next sign-in.</p>";
    }

    /** Minimal HTML escaping for the user-controlled id embedded in the notification body. */
    private static String escape(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;");
    }
}
