package org.jahia.modules.upa.mfa.totp.gql;

import graphql.annotations.annotationTypes.GraphQLDescription;
import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;
import org.jahia.modules.upa.mfa.MfaSession;
import org.jahia.modules.upa.mfa.gql.Result;

/**
 * TOTP preparation marker. TOTP has nothing to send to the user during prepare, but the payload
 * carries the {@code skipped} flag so the login UI can auto-drain a factor that does not apply
 * to this session (site disabled, out of scope, or pick-one enforcement satisfied by another
 * factor) by calling {@code verify} with an empty submission.
 */
@GraphQLName("MfaTotpPreparation")
@GraphQLDescription("TOTP preparation result; skipped=true means the factor does not apply to this session.")
public class TotpPreparation extends Result {

    private final boolean skipped;

    public TotpPreparation(MfaSession session, boolean skipped) {
        super(session);
        this.skipped = skipped;
    }

    @GraphQLField
    @GraphQLName("skipped")
    @GraphQLDescription("True when the factor was skipped for this session — call verify with an empty code to drain it.")
    public boolean isSkipped() {
        return skipped;
    }
}
