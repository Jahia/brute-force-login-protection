package org.jahia.community.bruteforceloginprotection.graphql.types;

import graphql.annotations.annotationTypes.GraphQLDescription;
import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;
import org.jahia.community.bruteforceloginprotection.core.JailConfig;

@GraphQLName("BruteForceLoginProtectionJail")
@GraphQLDescription("Jail configuration (a named failure-tracking policy)")
public class GqlJail {

    private final JailConfig inner;

    public GqlJail(JailConfig inner) {
        this.inner = inner;
    }

    @GraphQLField @GraphQLName("name")
    public String getName() { return inner.getName(); }

    @GraphQLField @GraphQLName("enabled")
    public boolean isEnabled() { return inner.isEnabled(); }

    @GraphQLField @GraphQLName("maxRetry")
    public int getMaxRetry() { return inner.getMaxRetry(); }

    @GraphQLField @GraphQLName("findTimeSeconds")
    public int getFindTimeSeconds() {
        long v = inner.getFindTimeSec();
        return v > Integer.MAX_VALUE ? Integer.MAX_VALUE : (int) v;
    }

    @GraphQLField @GraphQLName("banTimeSeconds")
    public int getBanTimeSeconds() {
        long v = inner.getBanTimeSec();
        return v > Integer.MAX_VALUE ? Integer.MAX_VALUE : (int) v;
    }
}
