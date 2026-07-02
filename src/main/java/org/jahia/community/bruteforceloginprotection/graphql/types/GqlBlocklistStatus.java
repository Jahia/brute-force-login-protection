package org.jahia.community.bruteforceloginprotection.graphql.types;

import graphql.annotations.annotationTypes.GraphQLDescription;
import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;

@GraphQLName("BruteForceLoginProtectionBlocklistStatus")
@GraphQLDescription("Live status of the static + Tor exit-address blocklists on this cluster node")
public class GqlBlocklistStatus {

    private final int staticEntryCount;
    private final boolean torEnabled;
    private final String torUrl;
    private final long torRefreshSeconds;
    private final int torEntryCount;
    private final long torLastFetchMs;
    private final long torLastAttemptMs;
    private final String torLastError;
    private final long nowMs;

    @SuppressWarnings("java:S107") // status snapshot: one field per reported metric
    public GqlBlocklistStatus(int staticEntryCount, boolean torEnabled, String torUrl,
                              long torRefreshSeconds, int torEntryCount, long torLastFetchMs,
                              long torLastAttemptMs, String torLastError, long nowMs) {
        this.staticEntryCount = staticEntryCount;
        this.torEnabled = torEnabled;
        this.torUrl = torUrl;
        this.torRefreshSeconds = torRefreshSeconds;
        this.torEntryCount = torEntryCount;
        this.torLastFetchMs = torLastFetchMs;
        this.torLastAttemptMs = torLastAttemptMs;
        this.torLastError = torLastError;
        this.nowMs = nowMs;
    }

    @GraphQLField @GraphQLName("staticEntryCount")
    @GraphQLDescription("Number of valid CIDR entries in the static blocklist")
    public int getStaticEntryCount() { return staticEntryCount; }

    @GraphQLField @GraphQLName("torEnabled")
    public boolean isTorEnabled() { return torEnabled; }

    @GraphQLField @GraphQLName("torUrl")
    public String getTorUrl() { return torUrl; }

    @GraphQLField @GraphQLName("torRefreshSeconds")
    public long getTorRefreshSeconds() { return torRefreshSeconds; }

    @GraphQLField @GraphQLName("torEntryCount")
    @GraphQLDescription("Number of Tor exit addresses currently enforced on this node")
    public int getTorEntryCount() { return torEntryCount; }

    @GraphQLField @GraphQLName("torLastFetchTime")
    @GraphQLDescription("Epoch millis of the last successful fetch; null when never fetched")
    public Long getTorLastFetchTime() { return torLastFetchMs > 0 ? torLastFetchMs : null; }

    @GraphQLField @GraphQLName("torLastAttemptTime")
    @GraphQLDescription("Epoch millis of the last fetch attempt; null when never attempted")
    public Long getTorLastAttemptTime() { return torLastAttemptMs > 0 ? torLastAttemptMs : null; }

    @GraphQLField @GraphQLName("torLastError")
    @GraphQLDescription("Error of the most recent fetch attempt; null when the last attempt succeeded")
    public String getTorLastError() { return torLastError; }

    @GraphQLField @GraphQLName("torListAgeSeconds")
    @GraphQLDescription("Age of the currently enforced list in seconds; null when never fetched")
    public Long getTorListAgeSeconds() {
        return torLastFetchMs > 0 ? Math.max(0L, (nowMs - torLastFetchMs) / 1000L) : null;
    }
}
