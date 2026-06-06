package org.jahia.modules.upa.mfa.extensions.gql;

import graphql.annotations.annotationTypes.GraphQLDescription;
import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;

import java.util.Collections;
import java.util.List;

/**
 * Factor information scoped to the ACTIVE MFA sign-in session, exposed to the (anonymous)
 * login UI after the password step. Carries no user identifier: the subject is always the
 * session's own user, so a caller can only learn about the account whose password it already
 * proved.
 */
@GraphQLName("MfaExtensionsSessionFactors")
@GraphQLDescription("Factor information for the active MFA sign-in session")
public class MfaSessionFactorsResult {

    private final List<String> configuredFactors;

    public MfaSessionFactorsResult(List<String> configuredFactors) {
        this.configuredFactors = configuredFactors == null
                ? Collections.emptyList()
                : Collections.unmodifiableList(configuredFactors);
    }

    @GraphQLField
    @GraphQLName("configuredFactors")
    @GraphQLDescription("The factor types the session's user has configured and may verify with on this site. "
            + "Used to filter the login UI's factor chooser; an empty list means inline enrollment is ahead.")
    public List<String> getConfiguredFactors() {
        return configuredFactors;
    }
}
