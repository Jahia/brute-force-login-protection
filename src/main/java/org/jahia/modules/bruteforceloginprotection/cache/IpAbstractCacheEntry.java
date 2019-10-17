package org.jahia.modules.bruteforceloginprotection.cache;

import java.io.Serializable;

/**
 *
 * @author fbourasse
 */
public abstract class IpAbstractCacheEntry implements Serializable{
    private static final long serialVersionUID = -6551768615414069547L;

    private String ip;

    public final String getIp() {
        return ip;
    }

    public final void setIp(String ip) {
        this.ip = ip;
    }
}
