package org.jahia.community.bruteforceloginprotection.graphql.types;

import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;
import org.jahia.community.bruteforceloginprotection.core.AuditLogger;

@GraphQLName("BruteForceLoginProtectionAuditEntry")
public class GqlAuditEntry {

    private final AuditLogger.AuditEntry inner;

    public GqlAuditEntry(AuditLogger.AuditEntry inner) {
        this.inner = inner;
    }

    @GraphQLField @GraphQLName("id")
    public String getId() { return inner.getId(); }

    @GraphQLField @GraphQLName("timestamp")
    public long getTimestamp() { return inner.getTimestamp(); }

    @GraphQLField @GraphQLName("event")
    public String getEvent() { return inner.getEvent(); }

    @GraphQLField @GraphQLName("ip")
    public String getIp() { return inner.getIp(); }

    @GraphQLField @GraphQLName("jail")
    public String getJail() { return inner.getJail(); }

    @GraphQLField @GraphQLName("source")
    public String getSource() { return inner.getSource(); }

    @GraphQLField @GraphQLName("details")
    public String getDetails() { return inner.getDetails(); }
}
