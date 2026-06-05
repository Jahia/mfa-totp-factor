package org.jahia.modules.upa.mfa.totp.gql;

import graphql.annotations.annotationTypes.GraphQLDescription;
import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;
import org.jahia.modules.upa.mfa.MfaSession;
import org.jahia.modules.upa.mfa.gql.Result;

/**
 * Returned by {@code totp.enroll}. Contains the freshly-generated secret and the
 * otpauth URI for QR rendering.
 * <p>
 * <b>Security:</b> the {@code secret} and {@code otpauthUri} are disclosed exactly once
 * (during enrollment). They MUST NOT be logged.
 */
@GraphQLName("MfaTotpEnrollResult")
@GraphQLDescription("Result of TOTP enrollment initiation (secret + otpauth URI)")
public class TotpEnrollResult extends Result {

    private final String secret;
    private final String otpauthUri;
    private final String issuer;
    private final String accountName;

    public TotpEnrollResult(MfaSession session, String secret, String otpauthUri,
                            String issuer, String accountName) {
        super(session);
        this.secret = secret;
        this.otpauthUri = otpauthUri;
        this.issuer = issuer;
        this.accountName = accountName;
    }

    @GraphQLField
    @GraphQLName("secret")
    @GraphQLDescription("Base32-encoded shared secret. Shown once.")
    public String getSecret() { return secret; }

    @GraphQLField
    @GraphQLName("otpauthUri")
    @GraphQLDescription("otpauth:// provisioning URI for QR rendering. Shown once.")
    public String getOtpauthUri() { return otpauthUri; }

    @GraphQLField
    @GraphQLName("issuer")
    public String getIssuer() { return issuer; }

    @GraphQLField
    @GraphQLName("accountName")
    public String getAccountName() { return accountName; }
}
