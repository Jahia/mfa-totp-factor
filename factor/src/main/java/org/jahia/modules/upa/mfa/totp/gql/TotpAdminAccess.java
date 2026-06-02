package org.jahia.modules.upa.mfa.totp.gql;

import org.jahia.modules.graphql.provider.dxm.DataFetchingException;
import org.jahia.services.content.JCRNodeWrapper;
import org.jahia.services.content.JCRSessionFactory;
import org.jahia.services.content.JCRSessionWrapper;
import org.jahia.services.usermanager.JahiaUser;

import javax.jcr.RepositoryException;

/**
 * Shared site-administration permission gate for the per-site / admin TOTP GraphQL operations.
 * The up-front {@code hasPermission} check yields a friendly error; the JCR ACL on the write
 * remains the load-bearing guard.
 */
final class TotpAdminAccess {

    static final String SITE_ADMIN_PERMISSION = "siteAdminAccess";
    static final String ERROR_NOT_AUTHENTICATED = "factor.totp.not_authenticated";
    static final String ERROR_PERMISSION_DENIED = "factor.totp.permission_denied";
    static final String ERROR_INTERNAL = "factor.totp.internal_error";

    private TotpAdminAccess() {
        // utility
    }

    /**
     * Require that the current user is root or holds {@code siteAdminAccess} on the given site.
     * Returns the caller's JCR session for convenience (writes should reuse it).
     */
    static JCRSessionWrapper requireSiteAdmin(String siteKey) {
        JahiaUser user = JCRSessionFactory.getInstance().getCurrentUser();
        if (user == null) {
            throw new DataFetchingException(ERROR_NOT_AUTHENTICATED);
        }
        try {
            JCRSessionWrapper session = JCRSessionFactory.getInstance().getCurrentUserSession();
            JCRNodeWrapper siteNode = session.getNode("/sites/" + siteKey);
            if (!user.isRoot() && !siteNode.hasPermission(SITE_ADMIN_PERMISSION)) {
                throw new DataFetchingException(ERROR_PERMISSION_DENIED);
            }
            return session;
        } catch (RepositoryException e) {
            throw new DataFetchingException(ERROR_INTERNAL);
        }
    }
}
