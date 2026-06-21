package org.jahia.modules.bruteforceloginprotection.graphql;

import graphql.annotations.annotationTypes.GraphQLDescription;
import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;
import graphql.annotations.annotationTypes.GraphQLTypeExtension;
import org.jahia.modules.graphql.provider.dxm.DXGraphQLProvider;

@GraphQLTypeExtension(DXGraphQLProvider.Mutation.class)
@GraphQLDescription("Brute Force Login Protection mutations")
public class BruteForceLoginProtectionMutationExtension {

    private BruteForceLoginProtectionMutationExtension() {
        // utility
    }

    @GraphQLField
    @GraphQLName("bruteForceLoginProtection")
    @GraphQLDescription("Brute-force login protection mutation namespace")
    public static BruteForceLoginProtectionMutation bruteForceLoginProtection() {
        return new BruteForceLoginProtectionMutation();
    }
}
