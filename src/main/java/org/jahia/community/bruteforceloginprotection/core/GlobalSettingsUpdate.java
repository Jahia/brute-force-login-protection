package org.jahia.community.bruteforceloginprotection.core;

import java.util.List;

/**
 * Parameter object holding optional updates to the global settings.
 * Any field left {@code null} means "do not change". For {@code webhookSecret},
 * an empty string means "clear", a non-empty string means "replace".
 */
public final class GlobalSettingsUpdate {

    private final Boolean activated;
    private final String whitelistIps;
    private final List<String> ignorePatterns;
    private final List<String> ignorePaths;
    private final Boolean trustProxyHeader;
    private final List<String> trustedProxyCidrs;
    private final Boolean emailEnabled;
    private final String emailRecipient;
    private final String webhookUrl;
    private final String webhookSecret;
    private final Integer auditLogMaxEntries;
    private final Double recidiveFactor;
    private final Integer maxBanTimeSeconds;
    private final String blocklistIps;
    private final Boolean torBlocklistEnabled;
    private final String torBlocklistUrl;
    private final Integer torBlocklistRefreshSeconds;

    private GlobalSettingsUpdate(Builder b) {
        this.activated = b.activated;
        this.whitelistIps = b.whitelistIps;
        this.ignorePatterns = b.ignorePatterns;
        this.ignorePaths = b.ignorePaths;
        this.trustProxyHeader = b.trustProxyHeader;
        this.trustedProxyCidrs = b.trustedProxyCidrs;
        this.emailEnabled = b.emailEnabled;
        this.emailRecipient = b.emailRecipient;
        this.webhookUrl = b.webhookUrl;
        this.webhookSecret = b.webhookSecret;
        this.auditLogMaxEntries = b.auditLogMaxEntries;
        this.recidiveFactor = b.recidiveFactor;
        this.maxBanTimeSeconds = b.maxBanTimeSeconds;
        this.blocklistIps = b.blocklistIps;
        this.torBlocklistEnabled = b.torBlocklistEnabled;
        this.torBlocklistUrl = b.torBlocklistUrl;
        this.torBlocklistRefreshSeconds = b.torBlocklistRefreshSeconds;
    }

    public Boolean getActivated() { return activated; }
    public String getWhitelistIps() { return whitelistIps; }
    public List<String> getIgnorePatterns() { return ignorePatterns; }
    public List<String> getIgnorePaths() { return ignorePaths; }
    public Boolean getTrustProxyHeader() { return trustProxyHeader; }
    public List<String> getTrustedProxyCidrs() { return trustedProxyCidrs; }
    public Boolean getEmailEnabled() { return emailEnabled; }
    public String getEmailRecipient() { return emailRecipient; }
    public String getWebhookUrl() { return webhookUrl; }
    public String getWebhookSecret() { return webhookSecret; }
    public Integer getAuditLogMaxEntries() { return auditLogMaxEntries; }
    public Double getRecidiveFactor() { return recidiveFactor; }
    public Integer getMaxBanTimeSeconds() { return maxBanTimeSeconds; }
    public String getBlocklistIps() { return blocklistIps; }
    public Boolean getTorBlocklistEnabled() { return torBlocklistEnabled; }
    public String getTorBlocklistUrl() { return torBlocklistUrl; }
    public Integer getTorBlocklistRefreshSeconds() { return torBlocklistRefreshSeconds; }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private Boolean activated;
        private String whitelistIps;
        private List<String> ignorePatterns;
        private List<String> ignorePaths;
        private Boolean trustProxyHeader;
        private List<String> trustedProxyCidrs;
        private Boolean emailEnabled;
        private String emailRecipient;
        private String webhookUrl;
        private String webhookSecret;
        private Integer auditLogMaxEntries;
        private Double recidiveFactor;
        private Integer maxBanTimeSeconds;
        private String blocklistIps;
        private Boolean torBlocklistEnabled;
        private String torBlocklistUrl;
        private Integer torBlocklistRefreshSeconds;

        public Builder activated(Boolean v) { this.activated = v; return this; }
        public Builder whitelistIps(String v) { this.whitelistIps = v; return this; }
        public Builder ignorePatterns(List<String> v) { this.ignorePatterns = v; return this; }
        public Builder ignorePaths(List<String> v) { this.ignorePaths = v; return this; }
        public Builder trustProxyHeader(Boolean v) { this.trustProxyHeader = v; return this; }
        public Builder trustedProxyCidrs(List<String> v) { this.trustedProxyCidrs = v; return this; }
        public Builder emailEnabled(Boolean v) { this.emailEnabled = v; return this; }
        public Builder emailRecipient(String v) { this.emailRecipient = v; return this; }
        public Builder webhookUrl(String v) { this.webhookUrl = v; return this; }
        public Builder webhookSecret(String v) { this.webhookSecret = v; return this; }
        public Builder auditLogMaxEntries(Integer v) { this.auditLogMaxEntries = v; return this; }
        public Builder recidiveFactor(Double v) { this.recidiveFactor = v; return this; }
        public Builder maxBanTimeSeconds(Integer v) { this.maxBanTimeSeconds = v; return this; }
        public Builder blocklistIps(String v) { this.blocklistIps = v; return this; }
        public Builder torBlocklistEnabled(Boolean v) { this.torBlocklistEnabled = v; return this; }
        public Builder torBlocklistUrl(String v) { this.torBlocklistUrl = v; return this; }
        public Builder torBlocklistRefreshSeconds(Integer v) { this.torBlocklistRefreshSeconds = v; return this; }

        public GlobalSettingsUpdate build() {
            return new GlobalSettingsUpdate(this);
        }
    }
}
