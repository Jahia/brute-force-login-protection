package org.jahia.modules.bruteforceloginprotection.cache;


import java.io.Serializable;

/**
 *
 * @author fbourasse
 */
public class IpCacheEntry extends IpAbstractCacheEntry implements Serializable {

    private static final long serialVersionUID = -1432235243384204528L;
    private int nbFailedLogins;

    public IpCacheEntry(String ip) {
        setIp(ip);
    }

    public int getNbFailedLogins() {
        return nbFailedLogins;
    }

    public void setNbFailedLogins(int nbFailedLogins) {
        this.nbFailedLogins = nbFailedLogins;
    }

}
