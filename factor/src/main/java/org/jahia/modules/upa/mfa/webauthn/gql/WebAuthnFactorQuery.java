package org.jahia.modules.upa.mfa.webauthn.gql;

import graphql.annotations.annotationTypes.GraphQLDescription;
import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;

/**
 * STUB GraphQL placeholder for the WebAuthn factor. Exposes {@code supported} (currently
 * {@code false}) so a client can detect the factor's availability before the implementation
 * lands, without any functional surface yet.
 */
@GraphQLName("MfaWebAuthnFactorQuery")
@GraphQLDescription("Read-only WebAuthn factor operations (stub).")
public class WebAuthnFactorQuery {

    @GraphQLField
    @GraphQLName("supported")
    @GraphQLDescription("Whether the WebAuthn factor is implemented and usable. Currently false (stub).")
    public boolean isSupported() {
        return false;
    }
}
