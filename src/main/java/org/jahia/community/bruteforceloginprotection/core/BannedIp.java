package org.jahia.community.bruteforceloginprotection.core;

import java.io.Serializable;

public class BannedIp implements Serializable {

    private static final long serialVersionUID = 1L;

    private String ip;
    private String jailName;
    private String sourceName;
    private long bannedAt;
    private long bannedUntil;
    private int banCount;
    private String reason;

    public BannedIp() {
        // for serialization
    }

    public BannedIp(String ip, String jailName, String sourceName, long bannedAt, long bannedUntil,
                    int banCount, String reason) {
        this.ip = ip;
        this.jailName = jailName;
        this.sourceName = sourceName;
        this.bannedAt = bannedAt;
        this.bannedUntil = bannedUntil;
        this.banCount = banCount;
        this.reason = reason;
    }

    public String getIp() { return ip; }
    public void setIp(String ip) { this.ip = ip; }
    public String getJailName() { return jailName; }
    public void setJailName(String jailName) { this.jailName = jailName; }
    public String getSourceName() { return sourceName; }
    public void setSourceName(String sourceName) { this.sourceName = sourceName; }
    public long getBannedAt() { return bannedAt; }
    public void setBannedAt(long bannedAt) { this.bannedAt = bannedAt; }
    public long getBannedUntil() { return bannedUntil; }
    public void setBannedUntil(long bannedUntil) { this.bannedUntil = bannedUntil; }
    public int getBanCount() { return banCount; }
    public void setBanCount(int banCount) { this.banCount = banCount; }
    public String getReason() { return reason; }
    public void setReason(String reason) { this.reason = reason; }

    public boolean isExpired(long now) {
        return bannedUntil > 0 && bannedUntil <= now;
    }
}
