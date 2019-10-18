package org.jahia.modules.bruteforceloginprotection.cache;

import java.io.Serializable;

/**
 *
 * @author fbourasse
 */
public final class SettingCacheEntry extends AbstractCacheEntry implements Serializable {

    private static final long serialVersionUID = -1432236243384204528L;
    private Object value;

    public SettingCacheEntry(String property, Object value) {
        setKey(property);
        setValue(value);
    }

    public Object getValue() {
        return value;
    }

    public void setValue(Object value) {
        this.value = value;
    }
}
