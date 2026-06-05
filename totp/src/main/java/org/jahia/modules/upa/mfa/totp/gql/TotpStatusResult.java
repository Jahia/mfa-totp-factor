package org.jahia.modules.upa.mfa.totp.gql;

import graphql.annotations.annotationTypes.GraphQLDescription;
import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;

@GraphQLName("MfaTotpStatusResult")
@GraphQLDescription("TOTP enrollment status for the current user")
public class TotpStatusResult {

    private final boolean enrolled;
    private final int remainingBackupCodes;

    public TotpStatusResult(boolean enrolled, int remainingBackupCodes) {
        this.enrolled = enrolled;
        this.remainingBackupCodes = remainingBackupCodes;
    }

    @GraphQLField
    @GraphQLName("enrolled")
    @GraphQLDescription("True if the user has an active TOTP enrollment")
    public boolean isEnrolled() {
        return enrolled;
    }

    @GraphQLField
    @GraphQLName("hasBackupCodes")
    @GraphQLDescription("True if at least one unused backup code remains")
    public boolean isHasBackupCodes() {
        return remainingBackupCodes > 0;
    }

    @GraphQLField
    @GraphQLName("remainingBackupCodes")
    @GraphQLDescription("Number of unused backup codes")
    public int getRemainingBackupCodes() {
        return remainingBackupCodes;
    }
}
