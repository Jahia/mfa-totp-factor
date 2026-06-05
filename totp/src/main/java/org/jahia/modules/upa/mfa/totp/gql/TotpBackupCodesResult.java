package org.jahia.modules.upa.mfa.totp.gql;

import graphql.annotations.annotationTypes.GraphQLDescription;
import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;
import org.jahia.modules.upa.mfa.MfaSession;
import org.jahia.modules.upa.mfa.gql.Result;

import java.util.Collections;
import java.util.List;

/**
 * Returned by {@code totp.regenerateBackupCodes}. Contains the newly-generated
 * plaintext backup codes; shown once.
 */
@GraphQLName("MfaTotpBackupCodesResult")
@GraphQLDescription("Fresh set of one-shot plaintext backup codes")
public class TotpBackupCodesResult extends Result {

    private final List<String> backupCodes;

    public TotpBackupCodesResult(MfaSession session, List<String> backupCodes) {
        super(session);
        this.backupCodes = backupCodes == null ? Collections.emptyList()
                : Collections.unmodifiableList(backupCodes);
    }

    @GraphQLField
    @GraphQLName("backupCodes")
    public List<String> getBackupCodes() {
        return backupCodes;
    }
}
