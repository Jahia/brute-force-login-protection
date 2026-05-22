package org.jahia.modules.bruteforceloginprotection.core;

import java.io.Serializable;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class BanContext implements Serializable {

    private static final long serialVersionUID = 1L;

    private final String ip;
    private final String jailName;
    private final String sourceName;
    private final long bannedAt;
    private final long bannedUntil;
    private final int banCount;
    private final String reason;
    private final Map<String, String> extras;

    private BanContext(Builder b) {
        this.ip = b.ip;
        this.jailName = b.jailName;
        this.sourceName = b.sourceName;
        this.bannedAt = b.bannedAt;
        this.bannedUntil = b.bannedUntil;
        this.banCount = b.banCount;
        this.reason = b.reason;
        this.extras = b.extras == null ? Collections.emptyMap() : new HashMap<>(b.extras);
    }

    public String getIp() { return ip; }
    public String getJailName() { return jailName; }
    public String getSourceName() { return sourceName; }
    public long getBannedAt() { return bannedAt; }
    public long getBannedUntil() { return bannedUntil; }
    public int getBanCount() { return banCount; }
    public String getReason() { return reason; }
    public Map<String, String> getExtras() { return extras; }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private String ip;
        private String jailName;
        private String sourceName;
        private long bannedAt;
        private long bannedUntil;
        private int banCount;
        private String reason;
        private Map<String, String> extras;

        public Builder ip(String v) { this.ip = v; return this; }
        public Builder jailName(String v) { this.jailName = v; return this; }
        public Builder sourceName(String v) { this.sourceName = v; return this; }
        public Builder bannedAt(long v) { this.bannedAt = v; return this; }
        public Builder bannedUntil(long v) { this.bannedUntil = v; return this; }
        public Builder banCount(int v) { this.banCount = v; return this; }
        public Builder reason(String v) { this.reason = v; return this; }
        public Builder extras(Map<String, String> v) { this.extras = v; return this; }

        public BanContext build() {
            return new BanContext(this);
        }
    }
}
