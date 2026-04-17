import {registry} from '@jahia/ui-extender';
import register from './BruteForceLoginProtection/register';
import i18next from 'i18next';

export default function () {
    registry.add('callback', 'brute-force-login-protection', {
        targets: ['jahiaApp-init:50'],
        callback: async () => {
            await i18next.loadNamespaces('brute-force-login-protection', () => {
                console.debug('%c brute-force-login-protection: i18n namespace loaded', 'color: #463CBA');
            });
            register();
            console.debug('%c brute-force-login-protection: activation completed', 'color: #463CBA');
        }
    });
}
