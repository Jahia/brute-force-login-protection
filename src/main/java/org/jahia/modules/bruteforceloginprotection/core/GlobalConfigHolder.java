package org.jahia.modules.bruteforceloginprotection.core;

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

import static org.jahia.modules.bruteforceloginprotection.BruteForceLoginProtectionConstants.*;

/**
 * OSGi {@link ManagedService} backing the global settings singleton PID. Properties are read from
 * {@code <jahia-var>/karaf/etc/org.jahia.modules.bruteforceloginprotection.global.cfg}; updates
 * persisted by the GraphQL mutation through {@link SettingsService} flow back here automatically.
 */
@Component(
        immediate = true,
        service = {GlobalConfigHolder.class, ManagedService.class},
        property = Constants.SERVICE_PID + "=" + GlobalConfigHolder.PID
)
public class GlobalConfigHolder implements ManagedService {

    public static final String PID = "org.jahia.modules.bruteforceloginprotection.global";
    private static final Logger LOGGER = LoggerFactory.getLogger(GlobalConfigHolder.class);

    // property keys in the .cfg
    public static final String CFG_ACTIVATED = "activated";
    public static final String CFG_WHITELIST = "whitelist_ips";
    public static final String CFG_IGNORE_PATTERNS = "ignore_patterns";
    public static final String CFG_TRUST_PROXY = "trust_x_forwarded_for";
    public static final String CFG_TRUSTED_PROXY_CIDRS = "trusted_proxy_cidrs";
    public static final String CFG_EMAIL_ENABLED = "email_enabled";
    public static final String CFG_EMAIL_RECIPIENT = "email_recipient";
    public static final String CFG_WEBHOOK_URL = "webhook_url";
    public static final String CFG_WEBHOOK_SECRET = "webhook_secret";
    public static final String CFG_AUDIT_LOG_MAX = "audit_log_max_entries";
    public static final String CFG_RECIDIVE_FACTOR = "recidive_factor";
    public static final String CFG_MAX_BAN_TIME_SEC = "max_ban_time_seconds";

    private final AtomicReference<GlobalSettings> current = new AtomicReference<>(defaults());

    @Override
    public void updated(Dictionary<String, ?> dictionary) throws ConfigurationException {
        if (dictionary == null) {
            current.set(defaults());
            return;
        }
        current.set(fromDictionary(dictionary));
        LOGGER.debug("BFLP: global settings reloaded from OSGi ConfigurationAdmin");
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
                .trustProxyHeader(false)
                .trustedProxyCidrs(Collections.emptyList())
                .emailEnabled(false)
                .auditLogMaxEntries(DEFAULT_AUDIT_LOG_MAX)
                .recidiveFactor(DEFAULT_RECIDIVE_FACTOR)
                .maxBanTimeSec(DEFAULT_MAX_BAN_TIME_SEC)
                .build();
    }

    static GlobalSettings fromDictionary(Dictionary<String, ?> d) {
        boolean activated = boolProp(d, CFG_ACTIVATED, false);
        String whitelist = stringProp(d, CFG_WHITELIST, DEFAULT_WHITELIST);
        List<String> ignore = stringListProp(d, CFG_IGNORE_PATTERNS);
        boolean trustProxy = boolProp(d, CFG_TRUST_PROXY, false);
        List<String> trustedProxyCidrs = stringListProp(d, CFG_TRUSTED_PROXY_CIDRS);
        boolean emailEnabled = boolProp(d, CFG_EMAIL_ENABLED, false);
        String emailRecipient = stringProp(d, CFG_EMAIL_RECIPIENT, null);
        String webhookUrl = stringProp(d, CFG_WEBHOOK_URL, null);
        String webhookSecret = WebhookSecretCodec.decrypt(stringProp(d, CFG_WEBHOOK_SECRET, null));
        int auditMax = (int) longProp(d, CFG_AUDIT_LOG_MAX, DEFAULT_AUDIT_LOG_MAX);
        double recidive = doubleProp(d, CFG_RECIDIVE_FACTOR, DEFAULT_RECIDIVE_FACTOR);
        long maxBan = longProp(d, CFG_MAX_BAN_TIME_SEC, DEFAULT_MAX_BAN_TIME_SEC);

        return GlobalSettings.builder()
                .activated(activated)
                .whitelistIps(whitelist)
                .ignorePatterns(ignore)
                .trustProxyHeader(trustProxy)
                .trustedProxyCidrs(trustedProxyCidrs)
                .emailEnabled(emailEnabled)
                .emailRecipient(emailRecipient)
                .webhookUrl(webhookUrl)
                .webhookSecret(webhookSecret)
                .auditLogMaxEntries(auditMax)
                .recidiveFactor(recidive)
                .maxBanTimeSec(maxBan)
                .build();
    }

    // --- helpers -----------------------------------------------------------------------------

    private static boolean boolProp(Dictionary<String, ?> d, String key, boolean def) {
        Object v = d.get(key);
        if (v == null) return def;
        if (v instanceof Boolean) return (Boolean) v;
        return Boolean.parseBoolean(String.valueOf(v).trim());
    }

    private static long longProp(Dictionary<String, ?> d, String key, long def) {
        Object v = d.get(key);
        if (v == null) return def;
        if (v instanceof Number) return ((Number) v).longValue();
        try {
            return Long.parseLong(String.valueOf(v).trim());
        } catch (NumberFormatException e) {
            return def;
        }
    }

    private static double doubleProp(Dictionary<String, ?> d, String key, double def) {
        Object v = d.get(key);
        if (v == null) return def;
        if (v instanceof Number) return ((Number) v).doubleValue();
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
        List<String> out = new ArrayList<>();
        if (v instanceof String[]) {
            for (String s : (String[]) v) {
                if (StringUtils.isNotBlank(s)) out.add(s.trim());
            }
        } else if (v instanceof Iterable<?>) {
            for (Object o : (Iterable<?>) v) {
                if (o != null && StringUtils.isNotBlank(o.toString())) out.add(o.toString().trim());
            }
        } else {
            for (String s : String.valueOf(v).split(",")) {
                if (StringUtils.isNotBlank(s)) out.add(s.trim());
            }
        }
        return out;
    }

}
