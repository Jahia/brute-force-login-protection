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

    private FailureEvent(Builder b) {
        this.ip = b.ip;
        this.sourceName = b.sourceName;
        this.jailName = b.jailName;
        this.timestampMs = b.timestampMs;
        this.username = b.username;
        this.userAgent = b.userAgent;
        this.requestPath = b.requestPath;
        this.extras = b.extras == null ? Collections.emptyMap() : new HashMap<>(b.extras);
    }

    public String getIp() { return ip; }
    public String getSourceName() { return sourceName; }
    public String getJailName() { return jailName; }
    public long getTimestampMs() { return timestampMs; }
    public String getUsername() { return username; }
    public String getUserAgent() { return userAgent; }
    public String getRequestPath() { return requestPath; }
    public Map<String, String> getExtras() { return extras; }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private String ip;
        private String sourceName;
        private String jailName;
        private long timestampMs;
        private String username;
        private String userAgent;
        private String requestPath;
        private Map<String, String> extras;

        public Builder ip(String v) { this.ip = v; return this; }
        public Builder sourceName(String v) { this.sourceName = v; return this; }
        public Builder jailName(String v) { this.jailName = v; return this; }
        public Builder timestampMs(long v) { this.timestampMs = v; return this; }
        public Builder username(String v) { this.username = v; return this; }
        public Builder userAgent(String v) { this.userAgent = v; return this; }
        public Builder requestPath(String v) { this.requestPath = v; return this; }
        public Builder extras(Map<String, String> v) { this.extras = v; return this; }

        public FailureEvent build() {
            return new FailureEvent(this);
        }
    }
}
