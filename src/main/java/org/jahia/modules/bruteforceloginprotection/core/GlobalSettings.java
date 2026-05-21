package org.jahia.modules.bruteforceloginprotection.core;

import java.io.Serializable;
import java.util.Collections;
import java.util.List;

public class GlobalSettings implements Serializable {

    private static final long serialVersionUID = 1L;

    private final boolean activated;
    private final String whitelistIps;
    private final List<String> ignorePatterns;
    private final boolean trustProxyHeader;
    private final boolean emailEnabled;
    private final String emailRecipient;
    private final String webhookUrl;
    private final String webhookSecret;
    private final int auditLogMaxEntries;
    private final double recidiveFactor;
    private final long maxBanTimeSec;

    public GlobalSettings(boolean activated, String whitelistIps, List<String> ignorePatterns,
                          boolean trustProxyHeader, boolean emailEnabled, String emailRecipient,
                          String webhookUrl, String webhookSecret, int auditLogMaxEntries,
                          double recidiveFactor, long maxBanTimeSec) {
        this.activated = activated;
        this.whitelistIps = whitelistIps;
        this.ignorePatterns = ignorePatterns == null ? Collections.emptyList() : Collections.unmodifiableList(ignorePatterns);
        this.trustProxyHeader = trustProxyHeader;
        this.emailEnabled = emailEnabled;
        this.emailRecipient = emailRecipient;
        this.webhookUrl = webhookUrl;
        this.webhookSecret = webhookSecret;
        this.auditLogMaxEntries = auditLogMaxEntries;
        this.recidiveFactor = recidiveFactor;
        this.maxBanTimeSec = maxBanTimeSec;
    }

    public boolean isActivated() { return activated; }
    public String getWhitelistIps() { return whitelistIps; }
    public List<String> getIgnorePatterns() { return ignorePatterns; }
    public boolean isTrustProxyHeader() { return trustProxyHeader; }
    public boolean isEmailEnabled() { return emailEnabled; }
    public String getEmailRecipient() { return emailRecipient; }
    public String getWebhookUrl() { return webhookUrl; }
    public String getWebhookSecret() { return webhookSecret; }
    public int getAuditLogMaxEntries() { return auditLogMaxEntries; }
    public double getRecidiveFactor() { return recidiveFactor; }
    public long getMaxBanTimeSec() { return maxBanTimeSec; }
}
