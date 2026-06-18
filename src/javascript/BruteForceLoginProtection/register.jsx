import {registry} from '@jahia/ui-extender';
import {BruteForceLoginProtectionAdmin} from './BruteForceLoginProtection';
import React from 'react';

export default () => {
    if (process.env.NODE_ENV !== 'production') {
        console.debug('%c brute-force-login-protection: activation in progress', 'color: #463CBA');
    }

    registry.add('adminRoute', 'bruteForceLoginProtection', {
        targets: ['administration-server-configuration:10'],
        requiredPermission: 'bruteForceLoginProtectionAdmin',
        label: 'brute-force-login-protection:label.menu_entry',
        isSelectable: true,
        render: () => React.createElement(BruteForceLoginProtectionAdmin)
    });
};
