package org.jahia.modules.bruteforceloginprotection.cache;

import java.io.Serializable;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 *
 * @author fbourasse
 */
public final class IpCacheEntry extends AbstractCacheEntry implements Serializable {

    private static final long serialVersionUID = -1432235243384204528L;
    private final AtomicInteger nbFailedLogins = new AtomicInteger();
    private final AtomicBoolean notificationSent = new AtomicBoolean();

    public IpCacheEntry(String ip) {
        setKey(ip);
    }

    public int getNbFailedLogins() {
        return nbFailedLogins.get();
    }

    public int incrementNbFailedLogins() {
        return nbFailedLogins.incrementAndGet();
    }

    public boolean isNotificationSent() {
        return notificationSent.get();
    }

    public boolean markNotificationSent() {
        return notificationSent.compareAndSet(false, true);
    }
}
