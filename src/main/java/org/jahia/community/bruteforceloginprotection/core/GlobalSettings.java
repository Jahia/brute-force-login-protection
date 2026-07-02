package org.jahia.community.bruteforceloginprotection.core;

import java.io.Serializable;
import java.util.Collections;
import java.util.List;

public class GlobalSettings implements Serializable {

    private static final long serialVersionUID = 1L;

    private final boolean activated;
    private final String whitelistIps;
    private final List<String> ignorePatterns;
    private final boolean trustProxyHeader;
    private final List<String> trustedProxyCidrs;
    private final boolean emailEnabled;
    private final String emailRecipient;
    private final String webhookUrl;
    private final String webhookSecret;
    private final int auditLogMaxEntries;
    private final double recidiveFactor;
    private final long maxBanTimeSec;
    private final String blocklistIps;
    private final boolean torBlocklistEnabled;
    private final String torBlocklistUrl;
    private final long torBlocklistRefreshSeconds;

    private GlobalSettings(Builder b) {
        this.activated = b.activated;
        this.whitelistIps = b.whitelistIps;
        this.ignorePatterns = b.ignorePatterns == null ? Collections.emptyList() : Collections.unmodifiableList(b.ignorePatterns);
        this.trustProxyHeader = b.trustProxyHeader;
        this.trustedProxyCidrs = b.trustedProxyCidrs == null ? Collections.emptyList() : Collections.unmodifiableList(b.trustedProxyCidrs);
        this.emailEnabled = b.emailEnabled;
        this.emailRecipient = b.emailRecipient;
        this.webhookUrl = b.webhookUrl;
        this.webhookSecret = b.webhookSecret;
        this.auditLogMaxEntries = b.auditLogMaxEntries;
        this.recidiveFactor = b.recidiveFactor;
        this.maxBanTimeSec = b.maxBanTimeSec;
        this.blocklistIps = b.blocklistIps;
        this.torBlocklistEnabled = b.torBlocklistEnabled;
        this.torBlocklistUrl = b.torBlocklistUrl;
        this.torBlocklistRefreshSeconds = b.torBlocklistRefreshSeconds;
    }

    public boolean isActivated() { return activated; }
    public String getWhitelistIps() { return whitelistIps; }
    public List<String> getIgnorePatterns() { return ignorePatterns; }
    public boolean isTrustProxyHeader() { return trustProxyHeader; }
    public List<String> getTrustedProxyCidrs() { return trustedProxyCidrs; }
    public boolean isEmailEnabled() { return emailEnabled; }
    public String getEmailRecipient() { return emailRecipient; }
    public String getWebhookUrl() { return webhookUrl; }
    public String getWebhookSecret() { return webhookSecret; }
    public int getAuditLogMaxEntries() { return auditLogMaxEntries; }
    public double getRecidiveFactor() { return recidiveFactor; }
    public long getMaxBanTimeSec() { return maxBanTimeSec; }
    public String getBlocklistIps() { return blocklistIps; }
    public boolean isTorBlocklistEnabled() { return torBlocklistEnabled; }
    public String getTorBlocklistUrl() { return torBlocklistUrl; }
    public long getTorBlocklistRefreshSeconds() { return torBlocklistRefreshSeconds; }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private boolean activated;
        private String whitelistIps;
        private List<String> ignorePatterns;
        private boolean trustProxyHeader;
        private List<String> trustedProxyCidrs;
        private boolean emailEnabled;
        private String emailRecipient;
        private String webhookUrl;
        private String webhookSecret;
        private int auditLogMaxEntries;
        private double recidiveFactor;
        private long maxBanTimeSec;
        private String blocklistIps;
        private boolean torBlocklistEnabled;
        private String torBlocklistUrl;
        private long torBlocklistRefreshSeconds;

        public Builder activated(boolean v) { this.activated = v; return this; }
        public Builder whitelistIps(String v) { this.whitelistIps = v; return this; }
        public Builder ignorePatterns(List<String> v) { this.ignorePatterns = v; return this; }
        public Builder trustProxyHeader(boolean v) { this.trustProxyHeader = v; return this; }
        public Builder trustedProxyCidrs(List<String> v) { this.trustedProxyCidrs = v; return this; }
        public Builder emailEnabled(boolean v) { this.emailEnabled = v; return this; }
        public Builder emailRecipient(String v) { this.emailRecipient = v; return this; }
        public Builder webhookUrl(String v) { this.webhookUrl = v; return this; }
        public Builder webhookSecret(String v) { this.webhookSecret = v; return this; }
        public Builder auditLogMaxEntries(int v) { this.auditLogMaxEntries = v; return this; }
        public Builder recidiveFactor(double v) { this.recidiveFactor = v; return this; }
        public Builder maxBanTimeSec(long v) { this.maxBanTimeSec = v; return this; }
        public Builder blocklistIps(String v) { this.blocklistIps = v; return this; }
        public Builder torBlocklistEnabled(boolean v) { this.torBlocklistEnabled = v; return this; }
        public Builder torBlocklistUrl(String v) { this.torBlocklistUrl = v; return this; }
        public Builder torBlocklistRefreshSeconds(long v) { this.torBlocklistRefreshSeconds = v; return this; }

        public GlobalSettings build() {
            return new GlobalSettings(this);
        }
    }
}
