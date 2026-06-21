package org.jahia.community.bruteforceloginprotection.spi;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Partial failure description returned by an {@link AuthFailureDetector}. The recorder
 * fills in ip, jail, timestamp, request path and user-agent.
 */
public final class FailureSignal {

    private final String sourceName;
    private final String username;
    private final Map<String, String> extras;

    private FailureSignal(Builder b) {
        this.sourceName = b.sourceName;
        this.username = b.username;
        this.extras = b.extras == null ? Collections.emptyMap() : new HashMap<>(b.extras);
    }

    public String getSourceName() {
        return sourceName;
    }

    public String getUsername() {
        return username;
    }

    public Map<String, String> getExtras() {
        return extras;
    }

    public static Builder builder(String sourceName) {
        return new Builder(sourceName);
    }

    public static final class Builder {
        private final String sourceName;
        private String username;
        private Map<String, String> extras;

        private Builder(String sourceName) {
            if (sourceName == null || sourceName.isEmpty()) {
                throw new IllegalArgumentException("sourceName is required");
            }
            this.sourceName = sourceName;
        }

        public Builder username(String value) {
            this.username = value;
            return this;
        }

        public Builder extra(String key, String value) {
            if (extras == null) {
                extras = new HashMap<>();
            }
            extras.put(key, value);
            return this;
        }

        public Builder extras(Map<String, String> values) {
            this.extras = values;
            return this;
        }

        public FailureSignal build() {
            return new FailureSignal(this);
        }
    }
}
