package org.jahia.modules.bruteforceloginprotection.cache;

import java.io.Serializable;

/**
 *
 * @author fbourasse
 */
public abstract class AbstractCacheEntry implements Serializable{
    private static final long serialVersionUID = -6551768615414069547L;

    private String key;

    public final String getKey() {
        return key;
    }

    public final void setKey(String key) {
        this.key = key;
    }
}
