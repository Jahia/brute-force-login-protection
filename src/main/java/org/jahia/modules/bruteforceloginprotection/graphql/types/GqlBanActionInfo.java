package org.jahia.modules.bruteforceloginprotection.graphql.types;

import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;

@GraphQLName("BruteForceLoginProtectionBanActionInfo")
public class GqlBanActionInfo {

    private final String name;
    private final String className;
    private final int priority;

    public GqlBanActionInfo(String name, String className, int priority) {
        this.name = name;
        this.className = className;
        this.priority = priority;
    }

    @GraphQLField @GraphQLName("name")
    public String getName() { return name; }

    @GraphQLField @GraphQLName("className")
    public String getClassName() { return className; }

    @GraphQLField @GraphQLName("priority")
    public int getPriority() { return priority; }
}
