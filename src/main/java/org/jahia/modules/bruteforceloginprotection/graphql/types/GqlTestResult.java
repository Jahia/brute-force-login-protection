package org.jahia.modules.bruteforceloginprotection.graphql.types;

import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;
import org.jahia.modules.bruteforceloginprotection.core.IntegrationTestResult;

@GraphQLName("BruteForceLoginProtectionTestResult")
public class GqlTestResult {

    private final boolean success;
    private final String message;

    public GqlTestResult(IntegrationTestResult result) {
        this.success = result.isSuccess();
        this.message = result.getMessage();
    }

    @GraphQLField @GraphQLName("success")
    public boolean isSuccess() { return success; }

    @GraphQLField @GraphQLName("message")
    public String getMessage() { return message; }
}
