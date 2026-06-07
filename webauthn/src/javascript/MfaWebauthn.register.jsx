import React from 'react';
import {registry} from '@jahia/ui-extender';
import {Security} from '@jahia/moonstone';
import MyWebauthnSettings from './MfaWebauthn/MyWebauthnSettings/MyWebauthnSettings';
import SiteSettings from './MfaWebauthn/SiteSettings/SiteSettings';
import AuditReporting from './MfaWebauthn/AuditReporting/AuditReporting';
import AuditReportSection from './MfaWebauthn/SiteSettings/AuditReportSection';

// Common guards for every per-site administration entry: site admins only, never on systemsite.
const SITE_ADMIN_GUARDS = {
    requiredSitePermission: 'siteAdminAccess',
    isEnabled: siteKey => siteKey !== 'systemsite'
};

export default function () {
    console.debug('%c mfa-factors-webauthn: activation in progress', 'color: #006633');

    // "MFA Community" group in the user dashboard. Children attach through the
    // 'dashboard-mfa-community-dashboard' target. Registered defensively because the totp and
    // webauthn bundles each may be installed alone — whichever activates first wins.
    if (!registry.get('adminRoute', 'mfa-community-dashboard')) {
        registry.add('adminRoute', 'mfa-community-dashboard', {
            targets: ['dashboard:99.2'],
            icon: <Security/>,
            label: 'mfa-factors-webauthn:mfaCommunity.menuLabel',
            isSelectable: false
        });
    }

    // MFA Community > Security keys and passkeys: register / rename / remove passkeys.
    registry.add('adminRoute', 'mfa-factors-webauthn', {
        targets: ['dashboard-mfa-community-dashboard:2'],
        icon: <Security/>,
        label: 'mfa-factors-webauthn:title',
        isSelectable: true,
        render: () => React.createElement(MyWebauthnSettings)
    });

    // "MFA Community" group in site administration. Children attach through the
    // 'administration-sites-mfa-community' target. Registered defensively because the totp and
    // webauthn bundles each may be installed alone — whichever activates first wins.
    if (!registry.get('adminRoute', 'mfa-community')) {
        registry.add('adminRoute', 'mfa-community', {
            targets: ['administration-sites:90'],
            icon: <Security/>,
            label: 'mfa-factors-webauthn:mfaCommunity.menuLabel',
            isSelectable: false,
            ...SITE_ADMIN_GUARDS
        });
    }

    // MFA Community > Security and passkeys: per-site WebAuthn policy (enable/enforce/grace/groups).
    registry.add('adminRoute', 'mfa-factors-webauthn-site-settings', {
        targets: ['administration-sites-mfa-community:3'],
        icon: <Security/>,
        label: 'mfa-factors-webauthn:siteSettings.menuLabel',
        isSelectable: true,
        ...SITE_ADMIN_GUARDS,
        render: () => React.createElement(SiteSettings)
    });

    // MFA Community > Audit & reporting: one page composing every factor's audit/report section
    // (registered below under the 'mfa-community-audit-section' type). Guarded like the group.
    if (!registry.get('adminRoute', 'mfa-community-audit')) {
        registry.add('adminRoute', 'mfa-community-audit', {
            targets: ['administration-sites-mfa-community:4'],
            icon: <Security/>,
            label: 'mfa-factors-webauthn:auditReporting.menuLabel',
            isSelectable: true,
            ...SITE_ADMIN_GUARDS,
            render: () => React.createElement(AuditReporting)
        });
    }

    // WebAuthn's contribution to the shared Audit & reporting page.
    registry.add('mfa-community-audit-section', 'mfa-factors-webauthn', {
        priority: 2,
        component: AuditReportSection
    });
}
