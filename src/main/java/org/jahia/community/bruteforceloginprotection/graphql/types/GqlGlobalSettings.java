package org.jahia.community.bruteforceloginprotection.graphql.types;

import graphql.annotations.annotationTypes.GraphQLDescription;
import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;
import org.jahia.community.bruteforceloginprotection.core.GlobalSettings;

import java.util.List;

@GraphQLName("BruteForceLoginProtectionGlobalSettings")
@GraphQLDescription("Global settings for the brute-force login protection module")
public class GqlGlobalSettings {

    private final GlobalSettings inner;

    public GqlGlobalSettings(GlobalSettings inner) {
        this.inner = inner;
    }

    @GraphQLField @GraphQLName("activated")
    public boolean isActivated() { return inner.isActivated(); }

    @GraphQLField @GraphQLName("whitelistIps")
    public String getWhitelistIps() { return inner.getWhitelistIps(); }

    @GraphQLField @GraphQLName("ignorePatterns")
    public List<String> getIgnorePatterns() { return inner.getIgnorePatterns(); }

    @GraphQLField @GraphQLName("ignorePaths")
    @GraphQLDescription("Literal URI substrings whose requests are exempt from failure detection")
    public List<String> getIgnorePaths() { return inner.getIgnorePaths(); }

    @GraphQLField @GraphQLName("trustProxyHeader")
    public boolean isTrustProxyHeader() { return inner.isTrustProxyHeader(); }

    @GraphQLField @GraphQLName("trustedProxyCidrs")
    public List<String> getTrustedProxyCidrs() { return inner.getTrustedProxyCidrs(); }

    @GraphQLField @GraphQLName("emailEnabled")
    public boolean isEmailEnabled() { return inner.isEmailEnabled(); }

    @GraphQLField @GraphQLName("emailRecipient")
    public String getEmailRecipient() { return inner.getEmailRecipient(); }

    @GraphQLField @GraphQLName("webhookUrl")
    public String getWebhookUrl() { return inner.getWebhookUrl(); }

    @GraphQLField @GraphQLName("webhookSecretConfigured")
    public boolean isWebhookSecretConfigured() {
        return inner.getWebhookSecret() != null && !inner.getWebhookSecret().isEmpty();
    }

    @GraphQLField @GraphQLName("auditLogMaxEntries")
    public int getAuditLogMaxEntries() { return inner.getAuditLogMaxEntries(); }

    @GraphQLField @GraphQLName("recidiveFactor")
    public double getRecidiveFactor() { return inner.getRecidiveFactor(); }

    @GraphQLField @GraphQLName("maxBanTimeSeconds")
    public int getMaxBanTimeSeconds() {
        long v = inner.getMaxBanTimeSec();
        return v > Integer.MAX_VALUE ? Integer.MAX_VALUE : (int) v;
    }

    @GraphQLField @GraphQLName("blocklistIps")
    public String getBlocklistIps() { return inner.getBlocklistIps(); }

    @GraphQLField @GraphQLName("torBlocklistEnabled")
    public boolean isTorBlocklistEnabled() { return inner.isTorBlocklistEnabled(); }

    @GraphQLField @GraphQLName("torBlocklistUrl")
    public String getTorBlocklistUrl() { return inner.getTorBlocklistUrl(); }

    @GraphQLField @GraphQLName("torBlocklistRefreshSeconds")
    public int getTorBlocklistRefreshSeconds() {
        long v = inner.getTorBlocklistRefreshSeconds();
        return v > Integer.MAX_VALUE ? Integer.MAX_VALUE : (int) v;
    }
}
