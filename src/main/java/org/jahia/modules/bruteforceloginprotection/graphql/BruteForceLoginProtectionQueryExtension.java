package org.jahia.modules.bruteforceloginprotection.graphql;

import graphql.annotations.annotationTypes.GraphQLDescription;
import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;
import graphql.annotations.annotationTypes.GraphQLTypeExtension;
import org.jahia.api.Constants;
import org.jahia.api.content.JCRTemplate;
import org.jahia.modules.bruteforceloginprotection.BruteForceLoginProtectionConstants;
import org.jahia.modules.graphql.provider.dxm.DXGraphQLProvider;
import org.jahia.modules.graphql.provider.dxm.security.GraphQLRequiresPermission;
import org.jahia.osgi.BundleUtils;
import org.jahia.services.content.JCRNodeWrapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jcr.RepositoryException;

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
                            return new GqlSettings(activated, nbFailedLoginMax, whitelistIps);
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

    @GraphQLName("BruteForceLoginProtectionSettings")
    @GraphQLDescription("Settings for the brute force login protection module")
    public static class GqlSettings {

        private final boolean activated;
        private final int nbFailedLoginMax;
        private final String whitelistIps;

        public GqlSettings(boolean activated, int nbFailedLoginMax, String whitelistIps) {
            this.activated = activated;
            this.nbFailedLoginMax = nbFailedLoginMax;
            this.whitelistIps = whitelistIps;
        }

        public static GqlSettings defaults() {
            return new GqlSettings(false, 6, "127.0.0.1/32,::1/128");
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
    }
}
