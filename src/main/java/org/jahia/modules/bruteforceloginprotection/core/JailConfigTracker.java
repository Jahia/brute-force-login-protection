package org.jahia.modules.bruteforceloginprotection.core;

import org.apache.commons.lang.StringUtils;
import org.osgi.framework.Constants;
import org.osgi.service.cm.ConfigurationException;
import org.osgi.service.cm.ManagedServiceFactory;
import org.osgi.service.component.annotations.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.Dictionary;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.jahia.modules.bruteforceloginprotection.BruteForceLoginProtectionConstants.*;

/**
 * OSGi {@link ManagedServiceFactory} backing the per-jail configurations. Each Felix-installed
 * {@code org.jahia.modules.bruteforceloginprotection.jail-<discriminator>.cfg} produces one entry
 * here, keyed by its mandatory {@code name} property.
 */
@Component(
        immediate = true,
        service = {JailConfigTracker.class, ManagedServiceFactory.class},
        property = Constants.SERVICE_PID + "=" + JailConfigTracker.FACTORY_PID
)
public class JailConfigTracker implements ManagedServiceFactory {

    public static final String FACTORY_PID = "org.jahia.modules.bruteforceloginprotection.jail";
    public static final String CFG_NAME = "name";
    public static final String CFG_ENABLED = "enabled";
    public static final String CFG_MAX_RETRY = "max_retry";
    public static final String CFG_FIND_TIME = "find_time_seconds";
    public static final String CFG_BAN_TIME = "ban_time_seconds";

    private static final Logger LOGGER = LoggerFactory.getLogger(JailConfigTracker.class);

    /** Felix pid (factory-pid.discriminator) -> name */
    private final Map<String, String> pidToName = new ConcurrentHashMap<>();
    /** name -> JailConfig */
    private final Map<String, JailConfig> jails = new ConcurrentHashMap<>();

    @Override
    public String getName() {
        return "BFLP jail configuration factory";
    }

    @Override
    public void updated(String pid, Dictionary<String, ?> properties) throws ConfigurationException {
        if (properties == null) {
            deleted(pid);
            return;
        }
        String name = asString(properties.get(CFG_NAME));
        if (StringUtils.isBlank(name) || isUnsafeJailName(name)) {
            throw new ConfigurationException(CFG_NAME, "missing or unsafe jail name in pid=" + pid);
        }
        boolean enabled = asBool(properties.get(CFG_ENABLED), true);
        int maxRetry = (int) asLong(properties.get(CFG_MAX_RETRY), DEFAULT_MAX_RETRY);
        long findTime = asLong(properties.get(CFG_FIND_TIME), DEFAULT_FIND_TIME_SEC);
        long banTime = asLong(properties.get(CFG_BAN_TIME), DEFAULT_BAN_TIME_SEC);

        // If this PID previously mapped to another name (e.g. operator renamed), drop the old entry.
        String previousName = pidToName.put(pid, name);
        if (previousName != null && !previousName.equals(name)) {
            jails.remove(previousName);
        }
        jails.put(name, new JailConfig(name, enabled, maxRetry, findTime, banTime));
        LOGGER.debug("BFLP: jail '{}' updated (pid={})", name, pid);
    }

    @Override
    public void deleted(String pid) {
        String name = pidToName.remove(pid);
        if (name != null) {
            jails.remove(name);
            LOGGER.debug("BFLP: jail '{}' removed (pid={})", name, pid);
        }
    }

    public Map<String, JailConfig> getJails() {
        if (jails.isEmpty()) {
            // No .cfg deployed yet: surface the built-in default jail so the module still works
            // out-of-the-box. Operators can override by dropping the bundled default cfg into
            // karaf/etc, which Felix will pick up and replace this entry.
            Map<String, JailConfig> map = new HashMap<>();
            map.put(DEFAULT_JAIL_LOGIN, new JailConfig(DEFAULT_JAIL_LOGIN, true,
                    DEFAULT_MAX_RETRY, DEFAULT_FIND_TIME_SEC, DEFAULT_BAN_TIME_SEC));
            return Collections.unmodifiableMap(map);
        }
        return Collections.unmodifiableMap(new HashMap<>(jails));
    }

    /** True iff a {@code .cfg} for the given jail name has been registered via
     * {@link #updated(String, Dictionary)} — i.e. {@link #getJail(String)} would return the
     * persisted config rather than the synthetic default. Used by the GraphQL readiness probe
     * so tests can wait until a {@code saveJail} mutation has actually landed in this tracker. */
    public boolean hasJail(String name) {
        return name != null && jails.containsKey(name);
    }

    public JailConfig getJail(String name) {
        if (name == null) {
            return null;
        }
        JailConfig jc = jails.get(name);
        if (jc != null) {
            return jc;
        }
        return new JailConfig(name, true, DEFAULT_MAX_RETRY, DEFAULT_FIND_TIME_SEC, DEFAULT_BAN_TIME_SEC);
    }

    /** Returns the Felix PID currently bound to the given jail name, or {@code null}. */
    public String findPidByName(String name) {
        if (name == null) return null;
        for (Map.Entry<String, String> e : pidToName.entrySet()) {
            if (name.equals(e.getValue())) {
                return e.getKey();
            }
        }
        return null;
    }

    public static boolean isUnsafeJailName(String name) {
        return name == null || name.contains("/") || name.contains("\\")
                || name.contains("..") || name.contains(":");
    }

    private static String asString(Object v) {
        return v == null ? null : String.valueOf(v);
    }

    private static boolean asBool(Object v, boolean def) {
        if (v == null) return def;
        if (v instanceof Boolean) return (Boolean) v;
        return Boolean.parseBoolean(String.valueOf(v).trim());
    }

    private static long asLong(Object v, long def) {
        if (v == null) return def;
        if (v instanceof Number) return ((Number) v).longValue();
        try {
            return Long.parseLong(String.valueOf(v).trim());
        } catch (NumberFormatException e) {
            return def;
        }
    }
}
