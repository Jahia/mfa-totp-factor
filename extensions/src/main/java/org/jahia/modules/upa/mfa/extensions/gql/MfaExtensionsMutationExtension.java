package org.jahia.modules.upa.mfa.extensions.gql;

import graphql.annotations.annotationTypes.GraphQLDescription;
import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;
import graphql.annotations.annotationTypes.GraphQLTypeExtension;
import org.jahia.modules.graphql.provider.dxm.DXGraphQLProvider;
import org.jahia.modules.graphql.provider.dxm.DataFetchingException;
import org.jahia.modules.graphql.provider.dxm.security.GraphQLRequiresPermission;
import org.jahia.osgi.BundleUtils;
import org.osgi.service.cm.Configuration;
import org.osgi.service.cm.ConfigurationAdmin;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Dictionary;
import java.util.Hashtable;
import java.util.List;

/**
 * Adds the top-level {@code mfaExtensionsSaveConfiguration} mutation: validates and persists the
 * global MFA configuration through ConfigurationAdmin — Karaf writes the change back to
 * {@code <karaf>/etc/org.jahia.modules.mfa.extensions.cfg} and the consuming components
 * (MfaGlobalPolicy, MfaLoginGateFilter, MfaLoginLogoutProvider) hot-reload via {@code @Modified}.
 * Server-admin only.
 */
@GraphQLTypeExtension(DXGraphQLProvider.Mutation.class)
public class MfaExtensionsMutationExtension {

    private static final Logger logger = LoggerFactory.getLogger(MfaExtensionsMutationExtension.class);
    private static final String ERROR_INTERNAL = "mfaExtensions.internal_error";

    private MfaExtensionsMutationExtension() {
        // not instantiated
    }

    @GraphQLField
    @GraphQLName("mfaExtensionsSaveConfiguration")
    @GraphQLDescription("Save the global MFA configuration. A null argument leaves the key unchanged; an empty "
            + "value clears it. enforcedFactors entries must be registered factor types; graceDays 0..365; "
            + "whitelist entries must be valid IP literals or CIDR blocks. Server administrators only.")
    @GraphQLRequiresPermission("admin")
    public static MfaExtensionsConfiguration mfaExtensionsSaveConfiguration(
            @GraphQLName("enforcedFactors") List<String> enforcedFactors,
            @GraphQLName("graceDays") Integer graceDays,
            @GraphQLName("loginGateEnabled") Boolean loginGateEnabled,
            @GraphQLName("loginGateIpWhitelist") String loginGateIpWhitelist,
            @GraphQLName("loginUrl") String loginUrl,
            @GraphQLName("logoutUrl") String logoutUrl,
            @GraphQLName("resetNotifyEmail") String resetNotifyEmail,
            @GraphQLName("loginGateTrustForwardedFor") Boolean loginGateTrustForwardedFor) {
        MfaExtensionsConfigSupport.Update update = new MfaExtensionsConfigSupport.Update(
                enforcedFactors, graceDays, loginGateEnabled, loginGateIpWhitelist, loginUrl, logoutUrl,
                resetNotifyEmail, loginGateTrustForwardedFor);
        try {
            ConfigurationAdmin configAdmin = BundleUtils.getOsgiService(ConfigurationAdmin.class, null);
            if (configAdmin == null) {
                throw new DataFetchingException(ERROR_INTERNAL);
            }
            Configuration config = configAdmin.getConfiguration(MfaExtensionsConfigSupport.PID, null);
            Dictionary<String, Object> properties = config.getProperties();
            if (properties == null) {
                properties = new Hashtable<>();
            }
            applyValidated(properties, update);
            config.update(properties);
            logger.info("MFA extensions configuration saved");
            return MfaExtensionsConfigSupport.read(properties, MfaExtensionsQueryExtension.registeredFactors());
        } catch (IOException e) {
            logger.warn("Failed to save the MFA extensions configuration: {}", e.getMessage());
            throw new DataFetchingException(ERROR_INTERNAL);
        }
    }

    /** Translate a validation failure into the GraphQL error carrying its stable code. */
    private static void applyValidated(Dictionary<String, Object> properties,
                                       MfaExtensionsConfigSupport.Update update) {
        try {
            MfaExtensionsConfigSupport.applyUpdate(properties, update,
                    MfaExtensionsQueryExtension.registeredFactors());
        } catch (IllegalArgumentException e) {
            throw new DataFetchingException(e.getMessage());
        }
    }
}
