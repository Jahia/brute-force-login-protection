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

    public BanContext(String ip, String jailName, String sourceName, long bannedAt, long bannedUntil,
                      int banCount, String reason, Map<String, String> extras) {
        this.ip = ip;
        this.jailName = jailName;
        this.sourceName = sourceName;
        this.bannedAt = bannedAt;
        this.bannedUntil = bannedUntil;
        this.banCount = banCount;
        this.reason = reason;
        this.extras = extras == null ? Collections.emptyMap() : new HashMap<>(extras);
    }

    public String getIp() { return ip; }
    public String getJailName() { return jailName; }
    public String getSourceName() { return sourceName; }
    public long getBannedAt() { return bannedAt; }
    public long getBannedUntil() { return bannedUntil; }
    public int getBanCount() { return banCount; }
    public String getReason() { return reason; }
    public Map<String, String> getExtras() { return extras; }
}
