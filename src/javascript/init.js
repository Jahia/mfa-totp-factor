import {registry} from '@jahia/ui-extender';
import i18next from 'i18next';
import register from './MfaTotpFactor.register';

export default function () {
    registry.add('callback', 'mfa-totp-factor', {
        targets: ['jahiaApp-init:99'],
        callback: async () => {
            await i18next.loadNamespaces('mfa-totp-factor');
            register();
            console.debug('%c mfa-totp-factor: activation completed', 'color: #006633');
        }
    });
}
