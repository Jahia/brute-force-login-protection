package org.jahia.modules.bruteforceloginprotection.graphql.types;

import graphql.annotations.annotationTypes.GraphQLDescription;
import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;
import org.jahia.modules.bruteforceloginprotection.core.FailureWindow;

@GraphQLName("BruteForceLoginProtectionFailureWindow")
@GraphQLDescription("Currently tracked failures for an (ip, jail) pair (not yet banned)")
public class GqlFailureWindow {

    private final FailureWindow inner;

    public GqlFailureWindow(FailureWindow inner) {
        this.inner = inner;
    }

    @GraphQLField @GraphQLName("ip")
    public String getIp() { return inner.getIp(); }

    @GraphQLField @GraphQLName("jail")
    public String getJail() { return inner.getJailName(); }

    @GraphQLField @GraphQLName("failuresInWindow")
    public int getFailuresInWindow() { return inner.size(); }

    @GraphQLField @GraphQLName("oldestFailureAt")
    public Long getOldestFailureAt() { return inner.oldest(); }

    @GraphQLField @GraphQLName("lastFailureAt")
    public Long getLastFailureAt() { return inner.newest(); }
}
