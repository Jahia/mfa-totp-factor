import React from 'react';
import {registry} from '@jahia/ui-extender';
import {Security} from '@jahia/moonstone';
import MyWebauthnSettings from './MfaWebauthn/MyWebauthnSettings/MyWebauthnSettings';
import SiteSettings from './MfaWebauthn/SiteSettings/SiteSettings';

export default function () {
    console.debug('%c mfa-factors-webauthn: activation in progress', 'color: #006633');

    // Per-user dashboard route: register / rename / remove passkeys.
    registry.add('adminRoute', 'mfa-factors-webauthn', {
        targets: ['dashboard:99.3'],
        icon: <Security/>,
        label: 'mfa-factors-webauthn:title',
        isSelectable: true,
        render: () => React.createElement(MyWebauthnSettings)
    });

    // Per-site administration route: enable/enforce WebAuthn for the site.
    registry.add('adminRoute', 'mfa-factors-webauthn-site-settings', {
        targets: ['administration-sites:99'],
        icon: <Security/>,
        label: 'mfa-factors-webauthn:siteSettings.menuLabel',
        isSelectable: true,
        requiredSitePermission: 'siteAdminAccess',
        isEnabled: siteKey => siteKey !== 'systemsite',
        render: () => React.createElement(SiteSettings)
    });
}
