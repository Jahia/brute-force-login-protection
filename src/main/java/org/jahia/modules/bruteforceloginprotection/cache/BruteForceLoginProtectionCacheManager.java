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
public class BruteForceLoginProtectionCacheManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(BruteForceLoginProtectionCacheManager.class);
    private static final int TIME_TO_IDLE = 3600;
    public static final String BRUTE_FORCE_LOGIN_PROTECTION_CACHE = "BruteForceLoginProtectionCache";
    private Ehcache bruteForceLoginProtectionCache;

    public void start() {
        final EhCacheProvider cacheProvider = (EhCacheProvider) SpringContextSingleton.getInstance().getContext().getBean("ehCacheProvider");
        final CacheManager cacheManager = cacheProvider.getCacheManager();
        bruteForceLoginProtectionCache = cacheManager.getCache(BRUTE_FORCE_LOGIN_PROTECTION_CACHE);
        if (bruteForceLoginProtectionCache == null) {
            bruteForceLoginProtectionCache = createBruteForceLoginProtectionCache(cacheManager, BRUTE_FORCE_LOGIN_PROTECTION_CACHE);
        } else {
            bruteForceLoginProtectionCache.removeAll();
        }
    }

    public void stop() {
        // flush
        if (bruteForceLoginProtectionCache != null) {
            bruteForceLoginProtectionCache.removeAll();
        }
    }

    private Ehcache createBruteForceLoginProtectionCache(CacheManager cacheManager, String cacheName) {
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

    public void clearCacheEntryByKey(String key) {
        bruteForceLoginProtectionCache.remove(key);
    }

    public IpCacheEntry getCacheEntryByIp(String ip) {
        return (IpCacheEntry) CacheHelper.getObjectValue(bruteForceLoginProtectionCache, ip);
    }

    public void cacheIp(IpCacheEntry ipCacheEntry) {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Caching IP: {}", ipCacheEntry.getKey());
        }
        final ModuleClassLoaderAwareCacheEntry cacheEntry = new ModuleClassLoaderAwareCacheEntry(ipCacheEntry, "brute-force-login-protection");
        bruteForceLoginProtectionCache.put(new Element(ipCacheEntry.getKey(), cacheEntry));
    }

    public SettingCacheEntry getCacheEntryByProperty(String property) {
        return (SettingCacheEntry) CacheHelper.getObjectValue(bruteForceLoginProtectionCache, property);
    }

    public void cacheSetting(SettingCacheEntry settingCacheEntry) {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("Caching IP: {}", settingCacheEntry.getKey());
        }
        final ModuleClassLoaderAwareCacheEntry cacheEntry = new ModuleClassLoaderAwareCacheEntry(settingCacheEntry, "brute-force-login-protection");
        bruteForceLoginProtectionCache.put(new Element(settingCacheEntry.getKey(), cacheEntry));
    }
}
