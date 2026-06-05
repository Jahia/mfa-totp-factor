package org.jahia.modules.upa.mfa.totp.gql;

import graphql.annotations.annotationTypes.GraphQLDescription;
import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;
import org.jahia.modules.upa.mfa.MfaSession;
import org.jahia.modules.upa.mfa.gql.Result;

import java.util.Collections;
import java.util.List;

/**
 * Returned by {@code totp.confirmEnroll}. Contains the plaintext backup codes that are
 * disclosed exactly once. The server stores only PBKDF2 hashes after this point.
 */
@GraphQLName("MfaTotpConfirmEnrollResult")
@GraphQLDescription("Result of TOTP enrollment confirmation (one-shot backup codes)")
public class TotpConfirmEnrollResult extends Result {

    private final List<String> backupCodes;

    public TotpConfirmEnrollResult(MfaSession session, List<String> backupCodes) {
        super(session);
        this.backupCodes = backupCodes == null ? Collections.emptyList()
                : Collections.unmodifiableList(backupCodes);
    }

    @GraphQLField
    @GraphQLName("backupCodes")
    @GraphQLDescription("Plaintext single-use backup codes. Returned ONCE; the client MUST surface them to the user immediately.")
    public List<String> getBackupCodes() {
        return backupCodes;
    }
}
