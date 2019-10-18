package org.jahia.modules.bruteforceloginprotection.cache;

import java.io.Serializable;

/**
 *
 * @author fbourasse
 */
public final class IpCacheEntry extends AbstractCacheEntry implements Serializable {

    private static final long serialVersionUID = -1432235243384204528L;
    private int nbFailedLogins;
    private boolean notificationSent;

    public IpCacheEntry(String ip) {
        setKey(ip);
    }

    public int getNbFailedLogins() {
        return nbFailedLogins;
    }

    public void setNbFailedLogins(int nbFailedLogins) {
        this.nbFailedLogins = nbFailedLogins;
    }

    public boolean isNotificationSent() {
        return notificationSent;
    }

    public void setNotificationSent(boolean notificationSent) {
        this.notificationSent = notificationSent;
    }
}
