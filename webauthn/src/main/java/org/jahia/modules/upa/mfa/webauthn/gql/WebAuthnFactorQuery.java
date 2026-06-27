package org.jahia.modules.upa.mfa.webauthn.gql;

import graphql.annotations.annotationTypes.GraphQLDescription;
import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;
import graphql.annotations.annotationTypes.GraphQLNonNull;
import org.jahia.modules.graphql.provider.dxm.DataFetchingException;
import org.jahia.modules.graphql.provider.dxm.osgi.annotations.GraphQLOsgiService;
import org.jahia.modules.upa.mfa.extensions.MfaGraphqlAuth;
import org.jahia.modules.upa.mfa.webauthn.WebAuthnAuditLog;
import org.jahia.modules.upa.mfa.webauthn.WebAuthnCredentialStore;
import org.jahia.modules.upa.mfa.webauthn.WebAuthnSiteSettingsStore;
import org.jahia.services.usermanager.JahiaUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.jcr.RepositoryException;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Read-only GraphQL operations for the WebAuthn factor: the current user's credentials, the
 * per-site policy, and the admin audit / registration report.
 */
@GraphQLName("MfaWebauthnFactorQuery")
@GraphQLDescription("Read-only operations for the WebAuthn MFA factor")
public class WebAuthnFactorQuery {

    private static final Logger logger = LoggerFactory.getLogger(WebAuthnFactorQuery.class);
    private static final String ERROR_NOT_AUTHENTICATED = "factor.webauthn.not_authenticated";
    private static final String ERROR_INTERNAL = "factor.webauthn.internal_error";

    private static final int DEFAULT_AUDIT_LIMIT = 50;
    private static final int DEFAULT_REPORT_LIMIT = 200;

    private WebAuthnCredentialStore credentialStore;
    private WebAuthnSiteSettingsStore siteSettingsStore;
    private WebAuthnAuditLog auditLog;

    @Inject @GraphQLOsgiService
    public void setCredentialStore(WebAuthnCredentialStore credentialStore) { this.credentialStore = credentialStore; }

    @Inject @GraphQLOsgiService
    public void setSiteSettingsStore(WebAuthnSiteSettingsStore siteSettingsStore) { this.siteSettingsStore = siteSettingsStore; }

    @Inject @GraphQLOsgiService
    public void setAuditLog(WebAuthnAuditLog auditLog) { this.auditLog = auditLog; }

    @GraphQLField
    @GraphQLName("supported")
    @GraphQLDescription("Whether the WebAuthn factor is implemented and usable (always true now).")
    public boolean isSupported() {
        return true;
    }

    @GraphQLField
    @GraphQLName("status")
    @GraphQLDescription("WebAuthn registration status + credentials for the currently authenticated user.")
    public WebAuthnStatusResult status() {
        // Jahia resolves unauthenticated requests to GUEST, not null.
        JahiaUser user = MfaGraphqlAuth.currentNonGuestUser();
        if (user == null) {
            throw new DataFetchingException(ERROR_NOT_AUTHENTICATED);
        }
        try {
            List<WebAuthnCredentialResult> creds = credentialStore.listCredentials(user.getName()).stream()
                    .map(WebAuthnCredentialResult::new)
                    .collect(Collectors.toList());
            return new WebAuthnStatusResult(creds);
        } catch (RepositoryException e) {
            logger.warn("Failed to load WebAuthn status for {}: {}", user.getName(), e.getMessage());
            throw new DataFetchingException(ERROR_INTERNAL);
        }
    }

    @GraphQLField
    @GraphQLName("siteSettings")
    @GraphQLDescription("The per-site WebAuthn policy (public; the login UI reads it to decide whether to offer WebAuthn).")
    public WebAuthnSiteSettingsResult siteSettings(@GraphQLName("siteKey") @GraphQLNonNull String siteKey) {
        WebAuthnSiteSettingsStore.WebAuthnSiteSettings s = siteSettingsStore.load(siteKey);
        return new WebAuthnSiteSettingsResult(siteKey, s.isEnabled(), s.getEnabledGroups());
    }

    @GraphQLField
    @GraphQLName("auditEvents")
    @GraphQLDescription("Recent WebAuthn audit events for a site (newest first). Caller must be a site admin.")
    public List<WebAuthnAuditEventResult> auditEvents(
            @GraphQLName("siteKey") @GraphQLNonNull String siteKey,
            @GraphQLName("limit") Integer limit) {
        WebAuthnAdminAccess.requireSiteAdmin(siteKey);
        try {
            int cap = limit == null ? DEFAULT_AUDIT_LIMIT : limit;
            return auditLog.recentEvents(siteKey, cap).stream()
                    .map(WebAuthnAuditEventResult::new)
                    .collect(Collectors.toList());
        } catch (RepositoryException e) {
            throw new DataFetchingException(ERROR_INTERNAL);
        }
    }

    @GraphQLField
    @GraphQLName("enrollmentReport")
    @GraphQLDescription("Who has / hasn't registered a WebAuthn authenticator. Caller must be a site admin.")
    public WebAuthnEnrollmentReportResult enrollmentReport(
            @GraphQLName("siteKey") @GraphQLNonNull String siteKey,
            @GraphQLName("limit") Integer limit) {
        WebAuthnAdminAccess.requireSiteAdmin(siteKey);
        try {
            int cap = limit == null ? DEFAULT_REPORT_LIMIT : limit;
            return new WebAuthnEnrollmentReportResult(credentialStore.buildRegistrationReport(cap));
        } catch (RepositoryException e) {
            throw new DataFetchingException(ERROR_INTERNAL);
        }
    }
}
