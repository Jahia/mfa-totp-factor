package org.jahia.modules.upa.mfa.totp.gql;

import org.jahia.modules.graphql.provider.dxm.DXGraphQLExtensionsProvider;
import org.osgi.service.component.annotations.Component;

/**
 * Empty marker component so the {@code @GraphQLTypeExtension} classes in this package
 * are auto-discovered by the DX GraphQL provider.
 */
@Component(immediate = true)
public class ExtensionsAutoDiscovery implements DXGraphQLExtensionsProvider {
    // Auto-discovered.
}
