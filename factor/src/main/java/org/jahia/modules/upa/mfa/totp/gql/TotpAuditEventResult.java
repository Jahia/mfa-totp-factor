package org.jahia.modules.upa.mfa.totp.gql;

import graphql.annotations.annotationTypes.GraphQLDescription;
import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;
import org.jahia.modules.upa.mfa.totp.TotpAuditLog;

@GraphQLName("MfaTotpAuditEvent")
@GraphQLDescription("A single TOTP MFA audit event.")
public class TotpAuditEventResult {

    private final TotpAuditLog.AuditEvent event;

    public TotpAuditEventResult(TotpAuditLog.AuditEvent event) {
        this.event = event;
    }

    @GraphQLField
    @GraphQLName("eventType")
    @GraphQLDescription("e.g. enroll, confirmEnroll, verify, disable, regenerateBackupCodes, reset, lockout")
    public String getEventType() {
        return event.getEventType();
    }

    @GraphQLField
    @GraphQLName("outcome")
    @GraphQLDescription("success | failure | denied")
    public String getOutcome() {
        return event.getOutcome();
    }

    @GraphQLField
    @GraphQLName("userId")
    public String getUserId() {
        return event.getUserId();
    }

    @GraphQLField
    @GraphQLName("siteKey")
    public String getSiteKey() {
        return event.getSiteKey();
    }

    @GraphQLField
    @GraphQLName("timestamp")
    @GraphQLDescription("Event time in epoch milliseconds.")
    public long getTimestamp() {
        return event.getTimestamp();
    }

    @GraphQLField
    @GraphQLName("detail")
    public String getDetail() {
        return event.getDetail();
    }
}
