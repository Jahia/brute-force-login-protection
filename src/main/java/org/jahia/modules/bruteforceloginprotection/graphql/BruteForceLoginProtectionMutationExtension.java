package org.jahia.modules.bruteforceloginprotection.graphql;

import graphql.annotations.annotationTypes.GraphQLDescription;
import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;
import graphql.annotations.annotationTypes.GraphQLTypeExtension;
import org.jahia.api.Constants;
import org.jahia.api.content.JCRTemplate;
import org.jahia.modules.bruteforceloginprotection.cache.BruteForceLoginProtectionCacheManager;
import org.jahia.modules.bruteforceloginprotection.BruteForceLoginProtectionConstants;
import org.jahia.modules.graphql.provider.dxm.DXGraphQLProvider;
import org.jahia.modules.graphql.provider.dxm.security.GraphQLRequiresPermission;
import org.jahia.osgi.BundleUtils;
import org.jahia.services.cache.CacheHelper;
import org.jahia.services.content.JCRNodeWrapper;
import org.jahia.services.content.JCRSessionWrapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jcr.RepositoryException;

@GraphQLTypeExtension(DXGraphQLProvider.Mutation.class)
@GraphQLName("BruteForceLoginProtectionMutations")
@GraphQLDescription("Brute Force Login Protection mutations")
public class BruteForceLoginProtectionMutationExtension {

    private static final Logger LOGGER = LoggerFactory.getLogger(BruteForceLoginProtectionMutationExtension.class);

    static final String SETTINGS_NODE_PATH = BruteForceLoginProtectionConstants.NODE_PATH;

    private BruteForceLoginProtectionMutationExtension() {
    }

    @GraphQLField
    @GraphQLName("bruteForceLoginProtectionSaveSettings")
    @GraphQLDescription("Saves the brute force login protection settings and flushes the cache")
    @GraphQLRequiresPermission("admin")
    public static Boolean saveSettings(
            @GraphQLName("activated") Boolean activated,
            @GraphQLName("nbFailedLoginMax") Integer nbFailedLoginMax,
            @GraphQLName("whitelistIps") String whitelistIps,
            @GraphQLName("timeToIdle") @GraphQLDescription("Seconds of inactivity before a tracked IP is forgotten") Integer timeToIdle) {
        try {
            BundleUtils.getOsgiService(JCRTemplate.class, null)
                    .doExecuteWithSystemSessionAsUser(null, Constants.EDIT_WORKSPACE, null, session -> {
                        try {
                            JCRNodeWrapper node = getOrCreateSettingsNode(session);
                            node.setProperty(BruteForceLoginProtectionConstants.PROPERTY_ACTIVATED, Boolean.TRUE.equals(activated));
                            if (nbFailedLoginMax != null) {
                                node.setProperty(BruteForceLoginProtectionConstants.PROPERTY_NB_FAILED_LOGIN_MAX, nbFailedLoginMax.longValue());
                            }
                            if (whitelistIps != null) {
                                node.setProperty(BruteForceLoginProtectionConstants.PROPERTY_WHITELIST_IPS, whitelistIps);
                            }
                            if (timeToIdle != null && timeToIdle > 0) {
                                node.setProperty(BruteForceLoginProtectionConstants.PROPERTY_TIME_TO_IDLE, timeToIdle.longValue());
                            }
                            session.save();
                        } catch (RepositoryException e) {
                            LOGGER.error("Error saving brute force login protection settings", e);
                        }
                        return null;
                    });
            if (timeToIdle != null && timeToIdle > 0) {
                final BruteForceLoginProtectionCacheManager cacheManager = BundleUtils.getOsgiService(BruteForceLoginProtectionCacheManager.class, null);
                if (cacheManager != null) {
                    cacheManager.setTimeToIdle(timeToIdle);
                }
            }
            CacheHelper.flushEhcacheByName(BruteForceLoginProtectionCacheManager.BRUTE_FORCE_LOGIN_PROTECTION_CACHE, true);
            return Boolean.TRUE;
        } catch (RepositoryException e) {
            LOGGER.error("Error saving brute force login protection settings", e);
            return Boolean.FALSE;
        }
    }

    @GraphQLField
    @GraphQLName("bruteForceLoginProtectionFlushCache")
    @GraphQLDescription("Flushes the brute force login protection cache")
    @GraphQLRequiresPermission("admin")
    public static Boolean flushCache() {
        CacheHelper.flushEhcacheByName(BruteForceLoginProtectionCacheManager.BRUTE_FORCE_LOGIN_PROTECTION_CACHE, true);
        return Boolean.TRUE;
    }

    @GraphQLField
    @GraphQLName("bruteForceLoginProtectionUnblockIp")
    @GraphQLDescription("Removes a single IP from the tracking cache, unblocking it")
    @GraphQLRequiresPermission("admin")
    public static Boolean unblockIp(@GraphQLName("ip") @GraphQLDescription("The IP to unblock") String ip) {
        if (ip == null || ip.trim().isEmpty()) {
            return Boolean.FALSE;
        }
        final BruteForceLoginProtectionCacheManager cacheManager = BundleUtils.getOsgiService(BruteForceLoginProtectionCacheManager.class, null);
        if (cacheManager == null) {
            LOGGER.warn("BruteForceLoginProtectionCacheManager OSGi service is not available");
            return Boolean.FALSE;
        }
        cacheManager.clearCacheEntryByKey(ip.trim());
        return Boolean.TRUE;
    }

    private static JCRNodeWrapper getOrCreateSettingsNode(JCRSessionWrapper session) throws RepositoryException {
        if (session.nodeExists(SETTINGS_NODE_PATH)) {
            return session.getNode(SETTINGS_NODE_PATH);
        }
        JCRNodeWrapper settingsRoot = session.getNode(BruteForceLoginProtectionConstants.NODE_SETTINGS_PATH);
        JCRNodeWrapper node = settingsRoot.addNode(BruteForceLoginProtectionConstants.NODE_NAME, "jnt:bruteForceLoginProtection");
        node.setProperty(BruteForceLoginProtectionConstants.PROPERTY_WHITELIST_IPS, "127.0.0.1/32,::1/128");
        node.setProperty(BruteForceLoginProtectionConstants.PROPERTY_ACTIVATED, false);
        node.setProperty(BruteForceLoginProtectionConstants.PROPERTY_NB_FAILED_LOGIN_MAX, 6L);
        node.setProperty(BruteForceLoginProtectionConstants.PROPERTY_TIME_TO_IDLE, BruteForceLoginProtectionConstants.DEFAULT_TIME_TO_IDLE);
        return node;
    }
}
