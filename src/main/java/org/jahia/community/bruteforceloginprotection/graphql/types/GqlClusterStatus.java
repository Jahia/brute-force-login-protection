package org.jahia.community.bruteforceloginprotection.graphql.types;

import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;

@GraphQLName("BruteForceLoginProtectionClusterStatus")
public class GqlClusterStatus {

    private final boolean hazelcastRunning;
    private final int nodeCount;

    public GqlClusterStatus(boolean hazelcastRunning, int nodeCount) {
        this.hazelcastRunning = hazelcastRunning;
        this.nodeCount = nodeCount;
    }

    @GraphQLField @GraphQLName("hazelcastRunning")
    public boolean isHazelcastRunning() { return hazelcastRunning; }

    @GraphQLField @GraphQLName("nodeCount")
    public int getNodeCount() { return nodeCount; }
}
