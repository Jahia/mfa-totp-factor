package org.jahia.modules.upa.mfa.webauthn.gql;

import graphql.annotations.annotationTypes.GraphQLDescription;
import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;
import org.jahia.modules.upa.mfa.MfaSession;
import org.jahia.modules.upa.mfa.gql.Result;

/**
 * WebAuthn login preparation: carries the {@code navigator.credentials.get()} options JSON
 * (the assertion challenge + allowed credentials) the browser must pass to the authenticator.
 */
@GraphQLName("MfaWebauthnPreparation")
@GraphQLDescription("WebAuthn assertion preparation: PublicKeyCredentialRequestOptions for navigator.credentials.get().")
public class WebAuthnPreparation extends Result {

    private final String requestOptionsJson;
    private final boolean skipped;

    public WebAuthnPreparation(MfaSession session, String requestOptionsJson, boolean skipped) {
        super(session);
        this.requestOptionsJson = requestOptionsJson;
        this.skipped = skipped;
    }

    @GraphQLField
    @GraphQLName("publicKeyCredentialRequestOptions")
    @GraphQLDescription("JSON for navigator.credentials.get(); null when the factor was skipped for this session.")
    public String getPublicKeyCredentialRequestOptions() {
        return requestOptionsJson;
    }

    @GraphQLField
    @GraphQLName("skipped")
    @GraphQLDescription("True when the factor was skipped for this session — call verify with an empty assertion to drain it.")
    public boolean isSkipped() {
        return skipped;
    }
}
