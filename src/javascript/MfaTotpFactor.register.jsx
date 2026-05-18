import React from 'react';
import {registry} from '@jahia/ui-extender';
import {Security} from '@jahia/moonstone';
import MyMfaSettings from './MfaTotpFactor/MyMfaSettings/MyMfaSettings';


export default function () {
    console.debug('%c mfa-totp-factor: activation in progress', 'color: #006633');
    registry.add('adminRoute', 'mfa-totp-factor', {
        targets: ['dashboard:99.2'],
        icon: <Security/>,
        label: 'mfa-totp-factor:title',
        isSelectable: true,
        render: () => React.createElement(MyMfaSettings)
    });
}
