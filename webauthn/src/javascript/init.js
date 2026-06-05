import {registry} from '@jahia/ui-extender';
import i18next from 'i18next';
import register from './MfaWebauthn.register';

export default function () {
    registry.add('callback', 'mfa-factors-webauthn', {
        targets: ['jahiaApp-init:99'],
        callback: async () => {
            await i18next.loadNamespaces('mfa-factors-webauthn');
            register();
            console.debug('%c mfa-factors-webauthn: activation completed', 'color: #006633');
        }
    });
}
