import React from 'react';
import {registry} from '@jahia/ui-extender';
import {Security} from '@jahia/moonstone';
import MyMfaSettings from './MfaTotpFactor/MyMfaSettings/MyMfaSettings';
import SiteSettings from './MfaTotpFactor/SiteSettings/SiteSettings';

export default function () {
    console.debug('%c mfa-totp-factor: activation in progress', 'color: #006633');

    // Per-user dashboard route: enroll / disable / regenerate backup codes.
    registry.add('adminRoute', 'mfa-totp-factor', {
        targets: ['dashboard:99.2'],
        icon: <Security/>,
        label: 'mfa-totp-factor:title',
        isSelectable: true,
        render: () => React.createElement(MyMfaSettings)
    });

    // Per-site administration route: toggle TOTP MFA enabled/enforced for the site.
    // Only visible to users with siteAdminAccess on the current site; never appears on systemsite.
    registry.add('adminRoute', 'mfa-totp-factor-site-settings', {
        targets: ['administration-sites:99'],
        icon: <Security/>,
        label: 'mfa-totp-factor:siteSettings.menuLabel',
        isSelectable: true,
        requiredSitePermission: 'siteAdminAccess',
        isEnabled: siteKey => siteKey !== 'systemsite',
        render: () => React.createElement(SiteSettings)
    });
}
