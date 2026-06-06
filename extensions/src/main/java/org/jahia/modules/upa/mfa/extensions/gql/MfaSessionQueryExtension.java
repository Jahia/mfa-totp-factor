package org.jahia.modules.upa.mfa.extensions.gql;

import graphql.annotations.annotationTypes.GraphQLDescription;
import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;
import graphql.annotations.annotationTypes.GraphQLTypeExtension;
import graphql.schema.DataFetchingEnvironment;
import org.jahia.modules.graphql.provider.dxm.DXGraphQLProvider;
import org.jahia.modules.graphql.provider.dxm.DataFetchingException;
import org.jahia.modules.graphql.provider.dxm.util.ContextUtil;
import org.jahia.modules.upa.mfa.MfaService;
import org.jahia.modules.upa.mfa.MfaSession;
import org.jahia.modules.upa.mfa.extensions.MfaFactorDirectory;
import org.jahia.osgi.BundleUtils;

import javax.servlet.http.HttpServletRequest;

/**
 * Adds the top-level {@code mfaSessionFactors} query for the pre-authentication login UI: which
 * factors the user of the IN-FLIGHT MFA session (password already verified) has configured.
 * <p>
 * Security: the subject is derived exclusively from the server-side {@link MfaSession} — there
 * is no user argument, so the configured-factor disclosure is limited to the account whose
 * password the caller already proved (the standard post-password disclosure every chooser-based
 * MFA UI makes). Without an active session the query fails with {@code no_active_session}.
 */
@GraphQLTypeExtension(DXGraphQLProvider.Query.class)
public class MfaSessionQueryExtension {

    private static final String ERROR_NO_SESSION = "no_active_session";

    private MfaSessionQueryExtension() {
        // not instantiated
    }

    @GraphQLField
    @GraphQLName("mfaSessionFactors")
    @GraphQLDescription("Factor information for the active MFA sign-in session (post-password). "
            + "Fails with no_active_session when no MFA session is in flight.")
    public static MfaSessionFactorsResult mfaSessionFactors(DataFetchingEnvironment environment) {
        HttpServletRequest request = ContextUtil.getHttpServletRequest(environment.getGraphQlContext());
        MfaService mfaService = BundleUtils.getOsgiService(MfaService.class, null);
        MfaSession session = (mfaService == null || request == null) ? null : mfaService.getMfaSession(request);
        if (session == null) {
            throw new DataFetchingException(ERROR_NO_SESSION);
        }
        MfaFactorDirectory directory = BundleUtils.getOsgiService(MfaFactorDirectory.class, null);
        if (directory == null) {
            return new MfaSessionFactorsResult(null);
        }
        return new MfaSessionFactorsResult(directory.configuredFactorsForUser(
                session.getContext().getUserId(), session.getContext().getSiteKey()));
    }
}
