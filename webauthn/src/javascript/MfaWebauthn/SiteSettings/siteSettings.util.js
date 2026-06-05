/**
 * Resolve the current site key from the admin shell context, falling back to the URL path
 * (/.../sites/<siteKey>/...).
 */
export function resolveSiteKey() {
    const fromCtx = window.contextJsParameters && window.contextJsParameters.siteKey;
    if (fromCtx) {
        return fromCtx;
    }

    const match = /\/sites\/([^/]+)/.exec(window.location.pathname || '');
    return match ? match[1] : null;
}

/** Map a GraphQL/Apollo error to an i18n key for the admin screens. */
export function mapAdminError(err) {
    const gql = err && err.graphQLErrors && err.graphQLErrors[0];
    const msg = (gql && gql.message) || (err && err.message) || 'unknown_error';
    if (msg.indexOf('permission_denied') !== -1) {
        return 'siteSettings.errors.permissionDenied';
    }

    if (msg.indexOf('not_authenticated') !== -1) {
        return 'siteSettings.errors.notAuthenticated';
    }

    if (msg.indexOf('invalid_grace_days') !== -1) {
        return 'siteSettings.errors.invalidGraceDays';
    }

    return 'siteSettings.errors.generic';
}
