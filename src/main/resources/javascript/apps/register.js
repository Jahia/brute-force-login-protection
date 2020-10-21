window.jahia.i18n.loadNamespaces('brute-force-login-protection');

window.jahia.uiExtender.registry.add('adminRoute', 'bruteForceLoginProtection', {
    targets: ['administration-server-configuration:10'],
    requiredPermission: 'adminUsers',
    label: 'brute-force-login-protection:label',
    isSelectable: true,
    iframeUrl: window.contextJsParameters.contextPath + '/cms/adminframe/default/$lang/settings.bruteForceLoginProtection.html'
});