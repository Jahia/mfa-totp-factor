package org.jahia.modules.upa.mfa.webauthn.gql;

import graphql.annotations.annotationTypes.GraphQLDescription;
import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;
import graphql.annotations.annotationTypes.GraphQLTypeExtension;
import org.jahia.modules.graphql.provider.dxm.DXGraphQLProvider;

/**
 * Adds a top-level {@code mfaWebAuthn} field on the GraphQL {@code Query} (stub placeholder).
 */
@GraphQLTypeExtension(DXGraphQLProvider.Query.class)
public class WebAuthnFactorQueryExtension {

    private WebAuthnFactorQueryExtension() {
        // not instantiated
    }

    @GraphQLField
    @GraphQLName("mfaWebAuthn")
    @GraphQLDescription("Stub WebAuthn / FIDO2 factor placeholder.")
    public static WebAuthnFactorQuery mfaWebAuthn() {
        return new WebAuthnFactorQuery();
    }
}
