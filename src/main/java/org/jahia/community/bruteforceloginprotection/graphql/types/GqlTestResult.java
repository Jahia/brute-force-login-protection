package org.jahia.community.bruteforceloginprotection.graphql.types;

import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;
import org.jahia.community.bruteforceloginprotection.core.IntegrationTestResult;

@GraphQLName("BruteForceLoginProtectionTestResult")
public class GqlTestResult {

    private final boolean success;
    private final String message;

    public GqlTestResult(IntegrationTestResult result) {
        this.success = result.success();
        this.message = result.message();
    }

    @GraphQLField @GraphQLName("success")
    public boolean isSuccess() { return success; }

    @GraphQLField @GraphQLName("message")
    public String getMessage() { return message; }
}
