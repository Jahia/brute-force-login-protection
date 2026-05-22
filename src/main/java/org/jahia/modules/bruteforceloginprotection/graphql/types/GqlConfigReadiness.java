package org.jahia.modules.bruteforceloginprotection.graphql.types;

import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;

@GraphQLName("BruteForceLoginProtectionConfigReadiness")
public class GqlConfigReadiness {

    private final boolean globalReady;
    private final boolean jailReady;

    public GqlConfigReadiness(boolean globalReady, boolean jailReady) {
        this.globalReady = globalReady;
        this.jailReady = jailReady;
    }

    @GraphQLField @GraphQLName("globalReady")
    public boolean isGlobalReady() { return globalReady; }

    @GraphQLField @GraphQLName("jailReady")
    public boolean isJailReady() { return jailReady; }
}
