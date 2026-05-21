package org.jahia.modules.bruteforceloginprotection.spi;

import java.io.Serializable;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class FailureEvent implements Serializable {

    private static final long serialVersionUID = 1L;

    private final String ip;
    private final String sourceName;
    private final String jailName;
    private final long timestampMs;
    private final String username;
    private final String userAgent;
    private final String requestPath;
    private final Map<String, String> extras;

    public FailureEvent(String ip, String sourceName, String jailName, long timestampMs,
                        String username, String userAgent, String requestPath,
                        Map<String, String> extras) {
        this.ip = ip;
        this.sourceName = sourceName;
        this.jailName = jailName;
        this.timestampMs = timestampMs;
        this.username = username;
        this.userAgent = userAgent;
        this.requestPath = requestPath;
        this.extras = extras == null ? Collections.emptyMap() : new HashMap<>(extras);
    }

    public String getIp() { return ip; }
    public String getSourceName() { return sourceName; }
    public String getJailName() { return jailName; }
    public long getTimestampMs() { return timestampMs; }
    public String getUsername() { return username; }
    public String getUserAgent() { return userAgent; }
    public String getRequestPath() { return requestPath; }
    public Map<String, String> getExtras() { return extras; }
}
