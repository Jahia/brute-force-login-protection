package org.jahia.modules.bruteforceloginprotection.cache;

import java.util.ArrayList;
import java.util.List;
import net.sf.ehcache.Cache;
import net.sf.ehcache.CacheManager;
import net.sf.ehcache.Ehcache;
import net.sf.ehcache.Element;
import net.sf.ehcache.config.CacheConfiguration;
import org.jahia.modules.bruteforceloginprotection.BruteForceLoginProtectionConstants;
import org.jahia.services.SpringContextSingleton;
import org.jahia.services.cache.CacheHelper;
import org.jahia.services.cache.ModuleClassLoaderAwareCacheEntry;
import org.jahia.services.cache.ehcache.EhCacheProvider;
import org.jahia.services.content.JCRNodeWrapper;
import org.jahia.services.content.JCRTemplate;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author fbourasse
 */
@Component(service = BruteForceLoginProtectionCacheManager.class, immediate = true)
public class BruteForceLoginProtectionCacheManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(BruteForceLoginProtectionCacheManager.class);
    public static final String BRUTE_FORCE_LOGIN_PROTECTION_CACHE = "BruteForceLoginProtectionCache";
    private Ehcache bruteForceLoginProtectionCache;

    @Activate
    public void start() {
        final EhCacheProvider cacheProvider = (EhCacheProvider) SpringContextSingleton.getInstance().getContext().getBean("ehCacheProvider");
        final CacheManager cacheManager = cacheProvider.getCacheManager();
        final int timeToIdle = readTimeToIdleFromJcr();
        bruteForceLoginProtectionCache = cacheManager.getCache(BRUTE_FORCE_LOGIN_PROTECTION_CACHE);
        if (bruteForceLoginProtectionCache == null) {
            bruteForceLoginProtectionCache = createBruteForceLoginProtectionCache(cacheManager, BRUTE_FORCE_LOGIN_PROTECTION_CACHE, timeToIdle);
        } else {
            bruteForceLoginProtectionCache.removeAll();
            bruteForceLoginProtectionCache.getCacheConfiguration().setTimeToIdleSeconds(timeToIdle);
        }
    }

    @Deactivate
    public void stop() {
        if (bruteForceLoginProtectionCache != null) {
            bruteForceLoginProtectionCache.removeAll();
        }
    }

    public void setTimeToIdle(int timeToIdle) {
        if (bruteForceLoginProtectionCache != null) {
            bruteForceLoginProtectionCache.getCacheConfiguration().setTimeToIdleSeconds(timeToIdle);
        }
    }

    private int readTimeToIdleFromJcr() {
        try {
            final Integer stored = JCRTemplate.getInstance().doExecuteWithSystemSessionAsUser(null, null, null, session -> {
                if (!session.nodeExists(BruteForceLoginProtectionConstants.NODE_PATH)) {
                    return BruteForceLoginProtectionConstants.DEFAULT_TIME_TO_IDLE;
                }
                final JCRNodeWrapper node = session.getNode(BruteForceLoginProtectionConstants.NODE_PATH);
                if (!node.hasProperty(BruteForceLoginProtectionConstants.PROPERTY_TIME_TO_IDLE)) {
                    return BruteForceLoginProtectionConstants.DEFAULT_TIME_TO_IDLE;
                }
                return (int) node.getProperty(BruteForceLoginProtectionConstants.PROPERTY_TIME_TO_IDLE).getLong();
            });
            return stored != null ? stored : BruteForceLoginProtectionConstants.DEFAULT_TIME_TO_IDLE;
        } catch (Exception e) {
            LOGGER.debug("Could not read timeToIdle from JCR on startup, using default of {}s",
                    BruteForceLoginProtectionConstants.DEFAULT_TIME_TO_IDLE);
            return BruteForceLoginProtectionConstants.DEFAULT_TIME_TO_IDLE;
        }
    }

    private Ehcache createBruteForceLoginProtectionCache(CacheManager cacheManager, String cacheName, int timeToIdle) {
        final CacheConfiguration cacheConfiguration = new CacheConfiguration();
        cacheConfiguration.setName(cacheName);
        cacheConfiguration.setTimeToIdleSeconds(timeToIdle);
        cacheConfiguration.setEternal(false);
        final Ehcache cache = new Cache(cacheConfiguration);
        cache.setName(cacheName);
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
            LOGGER.debug("Caching setting: {}", settingCacheEntry.getKey());
        }
        final ModuleClassLoaderAwareCacheEntry cacheEntry = new ModuleClassLoaderAwareCacheEntry(settingCacheEntry, "brute-force-login-protection");
        bruteForceLoginProtectionCache.put(new Element(settingCacheEntry.getKey(), cacheEntry));
    }

    public List<IpCacheEntry> getAllIpCacheEntries() {
        final List<IpCacheEntry> entries = new ArrayList<>();
        if (bruteForceLoginProtectionCache == null) {
            return entries;
        }
        for (Object key : bruteForceLoginProtectionCache.getKeys()) {
            if (key instanceof String) {
                final Object value = CacheHelper.getObjectValue(bruteForceLoginProtectionCache, (String) key);
                if (value instanceof IpCacheEntry) {
                    entries.add((IpCacheEntry) value);
                }
            }
        }
        return entries;
    }
}
