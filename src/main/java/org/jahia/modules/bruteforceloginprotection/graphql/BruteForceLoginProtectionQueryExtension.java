package org.jahia.modules.bruteforceloginprotection.graphql;

import graphql.annotations.annotationTypes.GraphQLDescription;
import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;
import graphql.annotations.annotationTypes.GraphQLTypeExtension;
import org.jahia.api.Constants;
import org.jahia.api.content.JCRTemplate;
import org.jahia.modules.bruteforceloginprotection.BruteForceLoginProtectionConstants;
import org.jahia.modules.bruteforceloginprotection.cache.BruteForceLoginProtectionCacheManager;
import org.jahia.modules.bruteforceloginprotection.cache.IpCacheEntry;
import org.jahia.modules.graphql.provider.dxm.DXGraphQLProvider;
import org.jahia.modules.graphql.provider.dxm.security.GraphQLRequiresPermission;
import org.jahia.osgi.BundleUtils;
import org.jahia.services.content.JCRNodeWrapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jcr.RepositoryException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@GraphQLTypeExtension(DXGraphQLProvider.Query.class)
@GraphQLName("BruteForceLoginProtectionQueries")
@GraphQLDescription("Brute Force Login Protection queries")
public class BruteForceLoginProtectionQueryExtension {

    private static final Logger LOGGER = LoggerFactory.getLogger(BruteForceLoginProtectionQueryExtension.class);

    private BruteForceLoginProtectionQueryExtension() {
    }

    @GraphQLField
    @GraphQLName("bruteForceLoginProtectionSettings")
    @GraphQLDescription("Returns the current brute force login protection settings")
    @GraphQLRequiresPermission("admin")
    public static GqlSettings settings() {
        try {
            return BundleUtils.getOsgiService(JCRTemplate.class, null)
                    .doExecuteWithSystemSessionAsUser(null, Constants.EDIT_WORKSPACE, null, session -> {
                        try {
                            if (!session.nodeExists(BruteForceLoginProtectionMutationExtension.SETTINGS_NODE_PATH)) {
                                return GqlSettings.defaults();
                            }
                            JCRNodeWrapper node = session.getNode(BruteForceLoginProtectionMutationExtension.SETTINGS_NODE_PATH);
                            boolean activated = node.hasProperty(BruteForceLoginProtectionConstants.PROPERTY_ACTIVATED)
                                    && node.getProperty(BruteForceLoginProtectionConstants.PROPERTY_ACTIVATED).getBoolean();
                            int nbFailedLoginMax = node.hasProperty(BruteForceLoginProtectionConstants.PROPERTY_NB_FAILED_LOGIN_MAX)
                                    ? (int) node.getProperty(BruteForceLoginProtectionConstants.PROPERTY_NB_FAILED_LOGIN_MAX).getLong()
                                    : 6;
                            String whitelistIps = node.hasProperty(BruteForceLoginProtectionConstants.PROPERTY_WHITELIST_IPS)
                                    ? node.getProperty(BruteForceLoginProtectionConstants.PROPERTY_WHITELIST_IPS).getString()
                                    : "127.0.0.1/32,::1/128";
                            int timeToIdle = node.hasProperty(BruteForceLoginProtectionConstants.PROPERTY_TIME_TO_IDLE)
                                    ? (int) node.getProperty(BruteForceLoginProtectionConstants.PROPERTY_TIME_TO_IDLE).getLong()
                                    : BruteForceLoginProtectionConstants.DEFAULT_TIME_TO_IDLE;
                            boolean trustProxyHeader = node.hasProperty(BruteForceLoginProtectionConstants.PROPERTY_TRUST_PROXY_HEADER)
                                    && node.getProperty(BruteForceLoginProtectionConstants.PROPERTY_TRUST_PROXY_HEADER).getBoolean();
                            return new GqlSettings(activated, nbFailedLoginMax, whitelistIps, timeToIdle, trustProxyHeader);
                        } catch (RepositoryException e) {
                            LOGGER.error("Error reading brute force login protection settings", e);
                            return GqlSettings.defaults();
                        }
                    });
        } catch (RepositoryException e) {
            LOGGER.error("Error reading brute force login protection settings", e);
            return GqlSettings.defaults();
        }
    }

    @GraphQLField
    @GraphQLName("bruteForceLoginProtectionTrackedIps")
    @GraphQLDescription("Returns the list of tracked IPs with their failed login counts")
    @GraphQLRequiresPermission("admin")
    public static List<GqlTrackedIp> trackedIps() {
        final BruteForceLoginProtectionCacheManager cacheManager = BundleUtils.getOsgiService(BruteForceLoginProtectionCacheManager.class, null);
        if (cacheManager == null) {
            return Collections.emptyList();
        }
        final GqlSettings currentSettings = settings();
        final int threshold = currentSettings.getNbFailedLoginMax();
        final List<IpCacheEntry> entries = cacheManager.getAllIpCacheEntries();
        final List<GqlTrackedIp> result = new ArrayList<>(entries.size());
        for (IpCacheEntry entry : entries) {
            result.add(new GqlTrackedIp(entry.getKey(), entry.getNbFailedLogins(), entry.getNbFailedLogins() >= threshold));
        }
        return result;
    }

    @GraphQLName("BruteForceLoginProtectionSettings")
    @GraphQLDescription("Settings for the brute force login protection module")
    public static class GqlSettings {

        private final boolean activated;
        private final int nbFailedLoginMax;
        private final String whitelistIps;
        private final int timeToIdle;
        private final boolean trustProxyHeader;

        public GqlSettings(boolean activated, int nbFailedLoginMax, String whitelistIps, int timeToIdle, boolean trustProxyHeader) {
            this.activated = activated;
            this.nbFailedLoginMax = nbFailedLoginMax;
            this.whitelistIps = whitelistIps;
            this.timeToIdle = timeToIdle;
            this.trustProxyHeader = trustProxyHeader;
        }

        public static GqlSettings defaults() {
            return new GqlSettings(false, 6, "127.0.0.1/32,::1/128", BruteForceLoginProtectionConstants.DEFAULT_TIME_TO_IDLE, false);
        }

        @GraphQLField
        @GraphQLName("activated")
        @GraphQLDescription("Whether the brute force login protection is active")
        public boolean isActivated() {
            return activated;
        }

        @GraphQLField
        @GraphQLName("nbFailedLoginMax")
        @GraphQLDescription("Maximum number of failed login attempts before an IP is blocked")
        public int getNbFailedLoginMax() {
            return nbFailedLoginMax;
        }

        @GraphQLField
        @GraphQLName("whitelistIps")
        @GraphQLDescription("Comma-separated list of CIDR blocks that are never blocked")
        public String getWhitelistIps() {
            return whitelistIps;
        }

        @GraphQLField
        @GraphQLName("timeToIdle")
        @GraphQLDescription("Seconds of inactivity before a tracked IP is forgotten from the cache")
        public int getTimeToIdle() {
            return timeToIdle;
        }

        @GraphQLField
        @GraphQLName("trustProxyHeader")
        @GraphQLDescription("Whether the X-Forwarded-For header is trusted as the client IP source")
        public boolean isTrustProxyHeader() {
            return trustProxyHeader;
        }
    }

    @GraphQLName("BruteForceLoginProtectionTrackedIp")
    @GraphQLDescription("A tracked IP with its failed login count and blocked status")
    public static class GqlTrackedIp {

        private final String ip;
        private final int nbFailedLogins;
        private final boolean blocked;

        public GqlTrackedIp(String ip, int nbFailedLogins, boolean blocked) {
            this.ip = ip;
            this.nbFailedLogins = nbFailedLogins;
            this.blocked = blocked;
        }

        @GraphQLField
        @GraphQLName("ip")
        @GraphQLDescription("The tracked IP address")
        public String getIp() {
            return ip;
        }

        @GraphQLField
        @GraphQLName("nbFailedLogins")
        @GraphQLDescription("Number of failed login attempts recorded for this IP")
        public int getNbFailedLogins() {
            return nbFailedLogins;
        }

        @GraphQLField
        @GraphQLName("blocked")
        @GraphQLDescription("Whether this IP currently exceeds the failed-login threshold")
        public boolean isBlocked() {
            return blocked;
        }
    }
}
