package org.jahia.modules.bruteforceloginprotection.cache;

import java.io.Serializable;

/**
 *
 * @author fbourasse
 */
public final class SettingCacheEntry extends AbstractCacheEntry implements Serializable {

    private static final long serialVersionUID = -1432236243384204528L;
    private Serializable value;

    public SettingCacheEntry(String property, Serializable value) {
        setKey(property);
        setValue(value);
    }

    public Serializable getValue() {
        return value;
    }

    public void setValue(Serializable value) {
        this.value = value;
    }
}
