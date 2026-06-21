package org.jahia.community.bruteforceloginprotection.core;

import java.io.Serializable;

public class JailConfig implements Serializable {

    private static final long serialVersionUID = 1L;

    private final String name;
    private final boolean enabled;
    private final int maxRetry;
    private final long findTimeSec;
    private final long banTimeSec;

    public JailConfig(String name, boolean enabled, int maxRetry, long findTimeSec, long banTimeSec) {
        this.name = name;
        this.enabled = enabled;
        this.maxRetry = maxRetry;
        this.findTimeSec = findTimeSec;
        this.banTimeSec = banTimeSec;
    }

    public String getName() { return name; }
    public boolean isEnabled() { return enabled; }
    public int getMaxRetry() { return maxRetry; }
    public long getFindTimeSec() { return findTimeSec; }
    public long getBanTimeSec() { return banTimeSec; }
}
