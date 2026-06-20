package org.jahia.modules.bruteforceloginprotection.graphql;

import graphql.annotations.annotationTypes.GraphQLDescription;
import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;
import graphql.annotations.annotationTypes.GraphQLTypeExtension;
import org.jahia.modules.graphql.provider.dxm.DXGraphQLProvider;

@GraphQLTypeExtension(DXGraphQLProvider.Query.class)
@GraphQLDescription("Brute Force Login Protection queries")
public class BruteForceLoginProtectionQueryExtension {

    private BruteForceLoginProtectionQueryExtension() {
        // utility
    }

    @GraphQLField
    @GraphQLName("bruteForceLoginProtection")
    @GraphQLDescription("Brute-force login protection query namespace")
    public static BruteForceLoginProtectionQuery bruteForceLoginProtection() {
        return new BruteForceLoginProtectionQuery();
    }
}
