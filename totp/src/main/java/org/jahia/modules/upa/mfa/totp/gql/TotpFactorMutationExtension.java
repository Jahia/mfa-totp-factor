package org.jahia.modules.upa.mfa.totp.gql;

import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;
import graphql.annotations.annotationTypes.GraphQLTypeExtension;
import org.jahia.modules.upa.mfa.gql.FactorsMutation;

/**
 * Adds the {@code totp} field on the UPA {@code FactorsMutation} GraphQL type.
 */
@GraphQLTypeExtension(FactorsMutation.class)
public class TotpFactorMutationExtension {

    private TotpFactorMutationExtension() {
        // not instantiated
    }

    @GraphQLField
    @GraphQLName("totp")
    public static TotpFactorMutation totp() {
        return new TotpFactorMutation();
    }
}
