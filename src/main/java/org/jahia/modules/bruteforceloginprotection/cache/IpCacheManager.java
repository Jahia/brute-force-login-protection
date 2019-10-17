package org.jahia.modules.bruteforceloginprotection.cache;

import net.sf.ehcache.Cache;
import net.sf.ehcache.CacheManager;
import net.sf.ehcache.Ehcache;
import net.sf.ehcache.Element;
import net.sf.ehcache.config.CacheConfiguration;
import org.jahia.services.SpringContextSingleton;
import org.jahia.services.cache.CacheHelper;
import org.jahia.services.cache.ModuleClassLoaderAwareCacheEntry;
import org.jahia.services.cache.ehcache.EhCacheProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author fbourasse
 */
public class IpCacheManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(IpCacheManager.class);
    private static final int TIME_TO_IDLE = 3600;
    public static final String IP_CACHE = "IpCache";
    private Ehcache ipCache;

    protected void start() {
        final EhCacheProvider cacheProvider = (EhCacheProvider) SpringContextSingleton.getInstance().getContext().getBean("ehCacheProvider");
        final CacheManager cacheManager = cacheProvider.getCacheManager();
        ipCache = cacheManager.getCache(IP_CACHE);
        if (ipCache == null) {
            ipCache = createIpCache(cacheManager, IP_CACHE);
        } else {
            ipCache.removeAll();
        }
    }

    protected void stop() {
        // flush
        if (ipCache != null) {
            ipCache.removeAll();
        }
    }

    private Ehcache createIpCache(CacheManager cacheManager, String cacheName) {
        final CacheConfiguration cacheConfiguration = new CacheConfiguration();
        cacheConfiguration.setName(cacheName);
        cacheConfiguration.setTimeToIdleSeconds(TIME_TO_IDLE);
        cacheConfiguration.setEternal(false);
        // Create a new cache with the configuration
        final Ehcache cache = new Cache(cacheConfiguration);
        cache.setName(cacheName);
        // Cache name has been set now we can initialize it by putting it in the manager.
        // Only Cache manager is initializing caches.
        return cacheManager.addCacheIfAbsent(cache);
    }

    public void clearCacheEntryByIp(String ip) {
        ipCache.remove(ip);
    }

    public IpCacheEntry getCacheEntryByIp(String ip) {
        return (IpCacheEntry) CacheHelper.getObjectValue(ipCache, ip);
    }

    public void cacheIp(IpCacheEntry ipCacheEntry) {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Caching IP: {}", ipCacheEntry.getIp());
        }
        final ModuleClassLoaderAwareCacheEntry cacheEntry = new ModuleClassLoaderAwareCacheEntry(ipCacheEntry, "brute-force-login-protection");
        ipCache.put(new Element(ipCacheEntry.getIp(), cacheEntry));
    }
}
