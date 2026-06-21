package org.jahia.community.bruteforceloginprotection.graphql.types;

import graphql.annotations.annotationTypes.GraphQLDescription;
import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;
import org.jahia.community.bruteforceloginprotection.core.BannedIp;

@GraphQLName("BruteForceLoginProtectionBannedIp")
public class GqlBannedIp {

    private final BannedIp inner;

    public GqlBannedIp(BannedIp inner) {
        this.inner = inner;
    }

    @GraphQLField @GraphQLName("ip")
    public String getIp() { return inner.getIp(); }

    @GraphQLField @GraphQLName("jail")
    public String getJail() { return inner.getJailName(); }

    @GraphQLField @GraphQLName("source")
    public String getSource() { return inner.getSourceName(); }

    @GraphQLField @GraphQLName("bannedAt")
    public long getBannedAt() { return inner.getBannedAt(); }

    @GraphQLField @GraphQLName("bannedUntil")
    public long getBannedUntil() { return inner.getBannedUntil(); }

    @GraphQLField @GraphQLName("banCount")
    public int getBanCount() { return inner.getBanCount(); }

    @GraphQLField @GraphQLName("reason")
    public String getReason() { return inner.getReason(); }

    @GraphQLField @GraphQLName("remainingSeconds")
    @GraphQLDescription("Seconds remaining until the ban expires (0 if already expired)")
    public int getRemainingSeconds() {
        long remaining = (inner.getBannedUntil() - System.currentTimeMillis()) / 1000L;
        if (remaining < 0) return 0;
        return remaining > Integer.MAX_VALUE ? Integer.MAX_VALUE : (int) remaining;
    }
}
