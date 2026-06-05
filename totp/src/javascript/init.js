import {registry} from '@jahia/ui-extender';
import i18next from 'i18next';
import register from './MfaTotpFactor.register';

export default function () {
    registry.add('callback', 'mfa-factors-totp', {
        targets: ['jahiaApp-init:99'],
        callback: async () => {
            await i18next.loadNamespaces('mfa-factors-totp');
            register();
            console.debug('%c mfa-factors-totp: activation completed', 'color: #006633');
        }
    });
}
