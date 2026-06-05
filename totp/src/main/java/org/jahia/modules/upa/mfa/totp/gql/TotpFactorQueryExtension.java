package org.jahia.modules.upa.mfa.totp.gql;

import graphql.annotations.annotationTypes.GraphQLDescription;
import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;
import graphql.annotations.annotationTypes.GraphQLTypeExtension;
import org.jahia.modules.graphql.provider.dxm.DXGraphQLProvider;

/**
 * Adds a top-level {@code mfaTotp} field on the GraphQL {@code Query} so the UI can read
 * the current user's enrollment status. We attach to {@code DXGraphQLProvider.Query}
 * rather than the UPA {@code Query} because the UPA {@code impl.gql} package is not
 * exported by the UPA API bundle.
 */
@GraphQLTypeExtension(DXGraphQLProvider.Query.class)
public class TotpFactorQueryExtension {

    private TotpFactorQueryExtension() {
        // not instantiated
    }

    @GraphQLField
    @GraphQLName("mfaTotp")
    @GraphQLDescription("Read-only TOTP factor operations")
    public static TotpFactorQuery mfaTotp() {
        return new TotpFactorQuery();
    }
}
