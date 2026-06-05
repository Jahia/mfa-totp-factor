package org.jahia.modules.upa.mfa.totp.gql;

import graphql.annotations.annotationTypes.GraphQLDescription;
import graphql.annotations.annotationTypes.GraphQLName;
import org.jahia.modules.upa.mfa.MfaSession;
import org.jahia.modules.upa.mfa.gql.Result;

/**
 * No-op preparation marker — TOTP has nothing to send to the user during prepare.
 */
@GraphQLName("MfaTotpPreparation")
@GraphQLDescription("TOTP preparation result (no-op for SPI uniformity)")
public class TotpPreparation extends Result {
    public TotpPreparation(MfaSession session) {
        super(session);
    }
}
