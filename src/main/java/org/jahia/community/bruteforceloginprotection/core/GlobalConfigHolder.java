package org.jahia.community.bruteforceloginprotection.core;

import org.apache.commons.lang.StringUtils;
import org.osgi.framework.Constants;
import org.osgi.service.cm.ConfigurationException;
import org.osgi.service.cm.ManagedService;
import org.osgi.service.component.annotations.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Dictionary;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.jahia.community.bruteforceloginprotection.BruteForceLoginProtectionConstants.*;

/**
 * OSGi {@link ManagedService} backing the global settings singleton PID. Properties are read from
 * {@code <jahia-var>/karaf/etc/org.jahia.community.bruteforceloginprotection.global.cfg}; updates
 * persisted by the GraphQL mutation through {@link SettingsService} flow back here automatically.
 */
@Component(
        immediate = true,
        service = {GlobalConfigHolder.class, ManagedService.class},
        property = Constants.SERVICE_PID + "=" + GlobalConfigHolder.PID
)
public class GlobalConfigHolder implements ManagedService {

    public static final String PID = "org.jahia.community.bruteforceloginprotection.global";
    private static final Logger LOGGER = LoggerFactory.getLogger(GlobalConfigHolder.class);

    // property keys in the .cfg
    public static final String CFG_ACTIVATED = "activated";
    public static final String CFG_WHITELIST = "whitelist_ips";
    public static final String CFG_IGNORE_PATTERNS = "ignore_patterns";
    public static final String CFG_IGNORE_PATHS = "ignore_paths";
    public static final String CFG_TRUST_PROXY = "trust_x_forwarded_for";
    public static final String CFG_TRUSTED_PROXY_CIDRS = "trusted_proxy_cidrs";
    public static final String CFG_EMAIL_ENABLED = "email_enabled";
    public static final String CFG_EMAIL_RECIPIENT = "email_recipient";
    public static final String CFG_WEBHOOK_URL = "webhook_url";
    public static final String CFG_WEBHOOK_SECRET = "webhook_secret";
    public static final String CFG_AUDIT_LOG_MAX = "audit_log_max_entries";
    public static final String CFG_RECIDIVE_FACTOR = "recidive_factor";
    public static final String CFG_MAX_BAN_TIME_SEC = "max_ban_time_seconds";
    public static final String CFG_BLOCKLIST = "blocklist_ips";
    public static final String CFG_TOR_ENABLED = "tor_blocklist_enabled";
    public static final String CFG_TOR_URL = "tor_blocklist_url";
    public static final String CFG_TOR_REFRESH_SEC = "tor_blocklist_refresh_seconds";

    private final AtomicReference<GlobalSettings> current = new AtomicReference<>(defaults());
    private volatile boolean updateReceived;

    @Override
    public void updated(Dictionary<String, ?> dictionary) throws ConfigurationException {
        if (dictionary == null) {
            current.set(defaults());
            updateReceived = true;
            return;
        }
        current.set(fromDictionary(dictionary));
        updateReceived = true;
        LOGGER.debug("BFLP: global settings reloaded from OSGi ConfigurationAdmin");
    }

    /** True once Felix has invoked {@link #updated} at least once — the in-memory snapshot
     * reflects ConfigurationAdmin rather than the cold-start defaults. Used by the GraphQL
     * readiness probe so tests can wait for a {@code saveGlobalSettings} mutation to round-trip
     * through the OSGi event dispatch before exercising the ban path. */
    public boolean isReady() {
        return updateReceived;
    }

    public GlobalSettings getGlobalSettings() {
        GlobalSettings g = current.get();
        return g != null ? g : defaults();
    }

    static GlobalSettings defaults() {
        return GlobalSettings.builder()
                .activated(false)
                .whitelistIps(DEFAULT_WHITELIST)
                .ignorePatterns(Collections.emptyList())
                .ignorePaths(Collections.emptyList())
                .trustProxyHeader(false)
                .trustedProxyCidrs(Collections.emptyList())
                .emailEnabled(false)
                .auditLogMaxEntries(DEFAULT_AUDIT_LOG_MAX)
                .recidiveFactor(DEFAULT_RECIDIVE_FACTOR)
                .maxBanTimeSec(DEFAULT_MAX_BAN_TIME_SEC)
                .torBlocklistEnabled(false)
                .torBlocklistUrl(DEFAULT_TOR_BLOCKLIST_URL)
                .torBlocklistRefreshSeconds(DEFAULT_TOR_REFRESH_SEC)
                .build();
    }

    /**
     * Applies the same {@link RegexSafetyCheck} lint the GraphQL save path applies, but
     * <strong>drops</strong> the offending entry instead of throwing.
     *
     * <p>The {@code .cfg} is a documented hand-edit surface, so the save-time lint is bypassable;
     * and grandfathered entries are deliberately allowed to persist through a save, so this is
     * where they are actually taken out of use. Dropping is the fail-safe direction: one exemption
     * fewer means the login failures it would have hidden are counted.
     *
     * <p>Per-entry rather than all-or-nothing, so one bad pattern cannot disable an operator's
     * other, legitimate exemptions.
     *
     * <p><strong>Never throw from here.</strong> {@code updated()} would abort before
     * {@code current.set(...)}, leaving the holder serving the previous snapshot — on a cold start
     * that is {@link #defaults()}, which has {@code activated=false}. A ReDoS lint whose failure
     * mode is "brute-force protection silently turned itself off" would repeat exactly the
     * inverted reasoning that caused GHSA-7qgr-2hqv-r344.
     */
    private static List<String> safeIgnorePatterns(List<String> raw) {
        List<String> safe = new ArrayList<>(raw.size());
        for (String p : raw) {
            try {
                RegexSafetyCheck.assertSafe(p);
                safe.add(p);
            } catch (IllegalArgumentException e) {
                LOGGER.warn("BFLP: dropping unsafe ignore_patterns entry '{}': {}. Failed logins for"
                        + " usernames it would have exempted are now counted and can lead to a ban.",
                        AuditLogger.sanitize(p), e.getMessage());
            }
        }
        return safe;
    }

    static GlobalSettings fromDictionary(Dictionary<String, ?> d) {
        boolean activated = boolProp(d, CFG_ACTIVATED, false);
        String whitelist = stringProp(d, CFG_WHITELIST, DEFAULT_WHITELIST);
        List<String> ignore = safeIgnorePatterns(stringListProp(d, CFG_IGNORE_PATTERNS));
        List<String> ignorePaths = stringListProp(d, CFG_IGNORE_PATHS);
        boolean trustProxy = boolProp(d, CFG_TRUST_PROXY, false);
        List<String> trustedProxyCidrs = stringListProp(d, CFG_TRUSTED_PROXY_CIDRS);
        boolean emailEnabled = boolProp(d, CFG_EMAIL_ENABLED, false);
        String emailRecipient = stringProp(d, CFG_EMAIL_RECIPIENT, null);
        String webhookUrl = stringProp(d, CFG_WEBHOOK_URL, null);
        String webhookSecret = WebhookSecretCodec.decrypt(stringProp(d, CFG_WEBHOOK_SECRET, null));
        int auditMax = (int) longProp(d, CFG_AUDIT_LOG_MAX, DEFAULT_AUDIT_LOG_MAX);
        double recidive = doubleProp(d, CFG_RECIDIVE_FACTOR, DEFAULT_RECIDIVE_FACTOR);
        long maxBan = longProp(d, CFG_MAX_BAN_TIME_SEC, DEFAULT_MAX_BAN_TIME_SEC);
        String blocklist = stringProp(d, CFG_BLOCKLIST, null);
        boolean torEnabled = boolProp(d, CFG_TOR_ENABLED, false);
        String torUrl = stringProp(d, CFG_TOR_URL, null);
        if (StringUtils.isBlank(torUrl)) {
            torUrl = DEFAULT_TOR_BLOCKLIST_URL;
        }
        // Clamp defensively: SettingsService clamps UI writes, but the .cfg can be hand-edited.
        long torRefresh = Math.max(MIN_TOR_REFRESH_SEC,
                Math.min(MAX_TOR_REFRESH_SEC, longProp(d, CFG_TOR_REFRESH_SEC, DEFAULT_TOR_REFRESH_SEC)));

        return GlobalSettings.builder()
                .activated(activated)
                .whitelistIps(whitelist)
                .ignorePatterns(ignore)
                .ignorePaths(ignorePaths)
                .trustProxyHeader(trustProxy)
                .trustedProxyCidrs(trustedProxyCidrs)
                .emailEnabled(emailEnabled)
                .emailRecipient(emailRecipient)
                .webhookUrl(webhookUrl)
                .webhookSecret(webhookSecret)
                .auditLogMaxEntries(auditMax)
                .recidiveFactor(recidive)
                .maxBanTimeSec(maxBan)
                .blocklistIps(blocklist)
                .torBlocklistEnabled(torEnabled)
                .torBlocklistUrl(torUrl)
                .torBlocklistRefreshSeconds(torRefresh)
                .build();
    }

    // --- helpers -----------------------------------------------------------------------------

    private static boolean boolProp(Dictionary<String, ?> d, String key, boolean def) {
        Object v = d.get(key);
        if (v == null) return def;
        if (v instanceof Boolean b) return b;
        return Boolean.parseBoolean(String.valueOf(v).trim());
    }

    private static long longProp(Dictionary<String, ?> d, String key, long def) {
        Object v = d.get(key);
        if (v == null) return def;
        if (v instanceof Number n) return n.longValue();
        try {
            return Long.parseLong(String.valueOf(v).trim());
        } catch (NumberFormatException e) {
            return def;
        }
    }

    private static double doubleProp(Dictionary<String, ?> d, String key, double def) {
        Object v = d.get(key);
        if (v == null) return def;
        if (v instanceof Number n) return n.doubleValue();
        try {
            return Double.parseDouble(String.valueOf(v).trim());
        } catch (NumberFormatException e) {
            return def;
        }
    }

    private static String stringProp(Dictionary<String, ?> d, String key, String def) {
        Object v = d.get(key);
        if (v == null) return def;
        return String.valueOf(v);
    }

    /**
     * Reads a list from either an array property or a comma-separated string property. Felix
     * .cfg files accept both, but most operators just write a single comma-separated line.
     */
    private static List<String> stringListProp(Dictionary<String, ?> d, String key) {
        Object v = d.get(key);
        if (v == null) {
            return Collections.emptyList();
        }
        if (v instanceof String[] arr) {
            return collectNonBlank(arr);
        }
        if (v instanceof Iterable<?> iterable) {
            return collectNonBlankIterable(iterable);
        }
        return collectNonBlank(String.valueOf(v).split(","));
    }

    private static List<String> collectNonBlank(String[] values) {
        List<String> out = new ArrayList<>();
        for (String s : values) {
            if (StringUtils.isNotBlank(s)) {
                out.add(s.trim());
            }
        }
        return out;
    }

    private static List<String> collectNonBlankIterable(Iterable<?> values) {
        List<String> out = new ArrayList<>();
        for (Object o : values) {
            if (o != null && StringUtils.isNotBlank(o.toString())) {
                out.add(o.toString().trim());
            }
        }
        return out;
    }

}
