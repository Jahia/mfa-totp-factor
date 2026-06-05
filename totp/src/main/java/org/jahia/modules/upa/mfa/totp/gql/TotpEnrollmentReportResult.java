package org.jahia.modules.upa.mfa.totp.gql;

import graphql.annotations.annotationTypes.GraphQLDescription;
import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;
import org.jahia.modules.upa.mfa.totp.TotpUserStore;

import java.util.List;

@GraphQLName("MfaTotpEnrollmentReport")
@GraphQLDescription("Aggregate enrollment report: totals plus the users who have not enrolled.")
public class TotpEnrollmentReportResult {

    private final TotpUserStore.EnrollmentReport report;

    public TotpEnrollmentReportResult(TotpUserStore.EnrollmentReport report) {
        this.report = report;
    }

    @GraphQLField
    @GraphQLName("totalUsers")
    @GraphQLDescription("Number of users scanned (capped).")
    public long getTotalUsers() {
        return report.getTotalUsers();
    }

    @GraphQLField
    @GraphQLName("enrolledUsers")
    @GraphQLDescription("Number of users currently enrolled in TOTP.")
    public long getEnrolledUsers() {
        return report.getEnrolledUsers();
    }

    @GraphQLField
    @GraphQLName("notEnrolled")
    @GraphQLDescription("User names that have not enrolled (capped list).")
    public List<String> getNotEnrolled() {
        return report.getNotEnrolled();
    }

    @GraphQLField
    @GraphQLName("truncated")
    @GraphQLDescription("True if the not-enrolled list or the user scan was capped.")
    public boolean isTruncated() {
        return report.isTruncated();
    }
}
