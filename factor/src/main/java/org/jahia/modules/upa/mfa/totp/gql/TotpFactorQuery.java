package org.jahia.modules.upa.mfa.totp.gql;

import graphql.annotations.annotationTypes.GraphQLDescription;
import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;
import graphql.annotations.annotationTypes.GraphQLNonNull;
import org.jahia.modules.graphql.provider.dxm.DataFetchingException;
import org.jahia.modules.graphql.provider.dxm.osgi.annotations.GraphQLOsgiService;
import org.jahia.modules.upa.mfa.totp.TotpAuditLog;
import org.jahia.modules.upa.mfa.totp.TotpSiteSettingsStore;
import org.jahia.modules.upa.mfa.totp.TotpUserStore;
import org.jahia.services.content.JCRSessionFactory;
import org.jahia.services.usermanager.JahiaUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.jcr.RepositoryException;
import java.util.List;
import java.util.stream.Collectors;

/**
 * GraphQL read-only operations for the TOTP factor.
 */
@GraphQLName("MfaTotpFactorQuery")
@GraphQLDescription("Read-only operations for the TOTP MFA factor")
public class TotpFactorQuery {

    private static final Logger logger = LoggerFactory.getLogger(TotpFactorQuery.class);
    private static final String ERROR_NOT_AUTHENTICATED = "factor.totp.not_authenticated";
    private static final String ERROR_INTERNAL = "factor.totp.internal_error";

    private static final int DEFAULT_AUDIT_LIMIT = 50;
    private static final int DEFAULT_REPORT_LIMIT = 200;

    private TotpUserStore userStore;
    private TotpSiteSettingsStore siteSettingsStore;
    private TotpAuditLog auditLog;

    @Inject
    @GraphQLOsgiService
    public void setUserStore(TotpUserStore userStore) {
        this.userStore = userStore;
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
    @GraphQLName("status")
    @GraphQLDescription("TOTP enrollment status for the currently authenticated user")
    public TotpStatusResult status() {
        JahiaUser user = JCRSessionFactory.getInstance().getCurrentUser();
        if (user == null) {
            throw new DataFetchingException(ERROR_NOT_AUTHENTICATED);
        }
        try {
            TotpUserStore.TotpUserSettings settings = userStore.load(user.getName());
            int remaining = settings.getBackupCodeHashes() == null ? 0 : settings.getBackupCodeHashes().size();
            return new TotpStatusResult(settings.isEnrolled(), remaining);
        } catch (RepositoryException e) {
            logger.warn("Failed to load TOTP settings for user {}: {}", user.getName(), e.getMessage());
            throw new DataFetchingException(ERROR_INTERNAL);
        }
    }

    @GraphQLField
    @GraphQLName("siteSettings")
    @GraphQLDescription("Per-site TOTP settings. Public-read so the login UI can decide whether to render a TOTP step at all.")
    public TotpSiteSettingsResult siteSettings(@GraphQLName("siteKey") @GraphQLNonNull String siteKey) {
        try {
            TotpSiteSettingsStore.TotpSiteSettings s = siteSettingsStore.load(siteKey);
            return new TotpSiteSettingsResult(siteKey, s.isEnabled(), s.isEnforced(),
                    s.getGraceDays(), s.getEnabledGroups());
        } catch (RepositoryException e) {
            logger.warn("Failed to load TOTP site settings for {}: {}", siteKey, e.getMessage());
            throw new DataFetchingException(ERROR_INTERNAL);
        }
    }

    @GraphQLField
    @GraphQLName("auditEvents")
    @GraphQLDescription("Recent TOTP audit events for a site (newest first). Requires site-administrator access.")
    public List<TotpAuditEventResult> auditEvents(
            @GraphQLName("siteKey") @GraphQLNonNull String siteKey,
            @GraphQLName("limit") Integer limit) {
        TotpAdminAccess.requireSiteAdmin(siteKey);
        try {
            return auditLog.recentEvents(siteKey, limit == null ? DEFAULT_AUDIT_LIMIT : limit).stream()
                    .map(TotpAuditEventResult::new)
                    .collect(Collectors.toList());
        } catch (RepositoryException e) {
            logger.warn("Failed to read TOTP audit events for {}: {}", siteKey, e.getMessage());
            throw new DataFetchingException(ERROR_INTERNAL);
        }
    }

    @GraphQLField
    @GraphQLName("enrollmentReport")
    @GraphQLDescription("Who has / hasn't enrolled in TOTP (enrollment is global). Requires site-administrator access.")
    public TotpEnrollmentReportResult enrollmentReport(
            @GraphQLName("siteKey") @GraphQLNonNull String siteKey,
            @GraphQLName("limit") Integer limit) {
        TotpAdminAccess.requireSiteAdmin(siteKey);
        try {
            return new TotpEnrollmentReportResult(
                    userStore.buildEnrollmentReport(limit == null ? DEFAULT_REPORT_LIMIT : limit));
        } catch (RepositoryException e) {
            logger.warn("Failed to build TOTP enrollment report: {}", e.getMessage());
            throw new DataFetchingException(ERROR_INTERNAL);
        }
    }
}
