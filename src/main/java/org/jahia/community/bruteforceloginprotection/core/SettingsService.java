package org.jahia.community.bruteforceloginprotection.core;

import org.apache.commons.lang.StringUtils;
import org.jahia.community.bruteforceloginprotection.CidrMatcher;
import org.jahia.community.bruteforceloginprotection.actions.WebhookUrlValidator;
import org.jahia.services.content.JCRNodeWrapper;
import org.jahia.services.content.JCRSessionWrapper;
import org.jahia.services.content.JCRTemplate;
import org.osgi.framework.InvalidSyntaxException;
import org.osgi.service.cm.Configuration;
import org.osgi.service.cm.ConfigurationAdmin;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jcr.RepositoryException;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Dictionary;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

import static org.jahia.community.bruteforceloginprotection.BruteForceLoginProtectionConstants.*;

/**
 * Facade in front of the OSGi-{@link ConfigurationAdmin}-backed configuration components
 * ({@link GlobalConfigHolder}, {@link JailConfigTracker}). Reads delegate to the in-memory
 * snapshots maintained by those components; writes go through {@code ConfigurationAdmin} so
 * Felix file-install rewrites the corresponding {@code .cfg} on disk.
 *
 * <p>This class also exposes {@link #getOrCreateSettingsNode(JCRSessionWrapper)} which is still
 * required by {@link AuditLogger} and {@code BruteForceTracker} to create the JCR parent node that
 * hosts the ban + audit child containers (those remain JCR-backed as runtime state).</p>
 */
@Component(immediate = true, service = SettingsService.class)
public class SettingsService {

    private static final Logger LOGGER = LoggerFactory.getLogger(SettingsService.class);

    private static final int AUDIT_LOG_MIN = 100;
    private static final int AUDIT_LOG_MAX = 100_000;

    // Sane upper bounds for jail numeric fields.
    private static final int JAIL_MAX_RETRY_MAX = 10_000;
    // ~10 years in seconds — rejects obviously absurd values while allowing very long windows/bans.
    private static final int JAIL_TIME_SECONDS_MAX = 315_360_000;

    @Reference
    private ConfigurationAdmin configurationAdmin;

    @Reference
    private GlobalConfigHolder globalConfigHolder;

    @Reference
    private JailConfigTracker jailConfigTracker;

    // JCR template is still needed: bans + audit log remain JCR-backed runtime state and need
    // the /settings/bruteforceloginprotection parent node to attach to. Tests inject this field
    // by reflection — do not rename without updating BruteForceTrackerTest.
    @Reference
    private JCRTemplate jcrTemplate;

    // -------------------------------------------------------------------------------------------
    // Read path — purely in-memory snapshots refreshed by the OSGi config listeners.
    // -------------------------------------------------------------------------------------------

    public GlobalSettings getGlobalSettings() {
        return globalConfigHolder != null
                ? globalConfigHolder.getGlobalSettings()
                : GlobalConfigHolder.defaults();
    }

    public Map<String, JailConfig> getJails() {
        return jailConfigTracker != null
                ? jailConfigTracker.getJails()
                : new JailConfigTracker().getJails();
    }

    public JailConfig getJail(String name) {
        return jailConfigTracker != null
                ? jailConfigTracker.getJail(name)
                : new JailConfig(name, true, DEFAULT_MAX_RETRY, DEFAULT_FIND_TIME_SEC, DEFAULT_BAN_TIME_SEC);
    }

    // -------------------------------------------------------------------------------------------
    // Write path — delegate to ConfigurationAdmin so Felix file-install persists to disk.
    // -------------------------------------------------------------------------------------------

    public boolean saveGlobalSettings(GlobalSettingsUpdate update) {
        if (update == null) {
            return false;
        }
        if (configurationAdmin == null) {
            LOGGER.error("BFLP: ConfigurationAdmin unavailable; cannot persist global settings");
            return false;
        }
        try {
            Configuration cfg = configurationAdmin.getConfiguration(GlobalConfigHolder.PID, "?");
            Dictionary<String, Object> props = cfg.getProperties();
            if (props == null) {
                props = new Hashtable<>();
            }
            applyGlobalUpdate(props, update);
            cfg.update(props);
            return true;
        } catch (IOException e) {
            LOGGER.error("BFLP: error saving global settings via ConfigurationAdmin", e);
            return false;
        }
    }

    private static void applyGlobalUpdate(Dictionary<String, Object> props, GlobalSettingsUpdate u) {
        applySimpleGlobalUpdate(props, u);
        applyWebhookSecretUpdate(props, u.getWebhookSecret());
        applyNumericGlobalUpdate(props, u);
    }

    private static void applySimpleGlobalUpdate(Dictionary<String, Object> props, GlobalSettingsUpdate u) {
        if (u.getActivated() != null) {
            props.put(GlobalConfigHolder.CFG_ACTIVATED, String.valueOf(u.getActivated()));
        }
        if (u.getWhitelistIps() != null) {
            props.put(GlobalConfigHolder.CFG_WHITELIST, u.getWhitelistIps());
        }
        if (u.getIgnorePatterns() != null) {
            for (String p : u.getIgnorePatterns()) {
                if (StringUtils.isNotBlank(p)) {
                    RegexSafetyCheck.assertSafe(p);
                }
            }
            props.put(GlobalConfigHolder.CFG_IGNORE_PATTERNS, joinList(u.getIgnorePatterns()));
        }
        if (u.getIgnorePaths() != null) {
            validateIgnorePaths(u.getIgnorePaths());
            props.put(GlobalConfigHolder.CFG_IGNORE_PATHS, joinList(u.getIgnorePaths()));
        }
        if (u.getTrustProxyHeader() != null) {
            props.put(GlobalConfigHolder.CFG_TRUST_PROXY, String.valueOf(u.getTrustProxyHeader()));
        }
        if (u.getTrustedProxyCidrs() != null) {
            props.put(GlobalConfigHolder.CFG_TRUSTED_PROXY_CIDRS, joinList(u.getTrustedProxyCidrs()));
        }
        if (u.getEmailEnabled() != null) {
            props.put(GlobalConfigHolder.CFG_EMAIL_ENABLED, String.valueOf(u.getEmailEnabled()));
        }
        if (u.getEmailRecipient() != null) {
            validateEmailRecipient(u.getEmailRecipient());
            props.put(GlobalConfigHolder.CFG_EMAIL_RECIPIENT, u.getEmailRecipient());
        }
        if (u.getWebhookUrl() != null) {
            if (!u.getWebhookUrl().isEmpty()) {
                WebhookUrlValidator.validateUrl(u.getWebhookUrl());
            }
            props.put(GlobalConfigHolder.CFG_WEBHOOK_URL, u.getWebhookUrl());
        }
        if (u.getBlocklistIps() != null) {
            validateBlocklistIps(u.getBlocklistIps());
            props.put(GlobalConfigHolder.CFG_BLOCKLIST, u.getBlocklistIps());
        }
        if (u.getTorBlocklistEnabled() != null) {
            props.put(GlobalConfigHolder.CFG_TOR_ENABLED, String.valueOf(u.getTorBlocklistEnabled()));
        }
        if (u.getTorBlocklistUrl() != null) {
            if (!u.getTorBlocklistUrl().isEmpty()) {
                validateTorUrl(u.getTorBlocklistUrl());
            }
            props.put(GlobalConfigHolder.CFG_TOR_URL, u.getTorBlocklistUrl());
        }
    }

    /**
     * Validates every comma-separated blocklist entry as CIDR (or bare IP) notation. Unlike the
     * whitelist (where malformed entries are skipped at match time for backward compatibility),
     * blocklist entries are validated strictly at save time: a typo here would silently NOT block
     * an address the operator believes is blocked.
     */
    static void validateBlocklistIps(String blocklist) {
        if (StringUtils.isBlank(blocklist)) {
            return;
        }
        for (String entry : blocklist.split(",")) {
            String trimmed = entry.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            try {
                new CidrMatcher(trimmed);
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("Invalid blocklist CIDR: " + AuditLogger.sanitize(trimmed));
            }
        }
    }

    // A single ignore-path entry is a literal URI substring; 512 chars is far beyond any real URL
    // fragment and bounds the per-request contains() work on the auth hot path.
    private static final int MAX_IGNORE_PATH_LENGTH = 512;

    /**
     * Validates each ignore-path entry (a literal URI substring matched by the auth valve). Rejects
     * control characters / CRLF — which would corrupt the {@code .cfg} line and could be replayed
     * into the audit log — and over-long entries. Blank entries are dropped by {@link #joinList} and
     * are harmless. Unlike {@code ignorePatterns} these are NOT regexes, so no ReDoS check applies.
     */
    static void validateIgnorePaths(List<String> ignorePaths) {
        if (ignorePaths == null) {
            return;
        }
        for (String entry : ignorePaths) {
            if (StringUtils.isBlank(entry)) {
                continue;
            }
            if (entry.length() > MAX_IGNORE_PATH_LENGTH) {
                throw new IllegalArgumentException("Ignore-path entry exceeds " + MAX_IGNORE_PATH_LENGTH + " characters");
            }
            for (int i = 0; i < entry.length(); i++) {
                char c = entry.charAt(i);
                if (c < 0x20 || c == 0x7F) {
                    throw new IllegalArgumentException("Ignore-path entry contains control characters");
                }
            }
        }
    }

    /**
     * Validates the Tor exit-address list URL: http/https scheme, a host, and no userinfo.
     * Deliberately does NOT reject private/internal addresses (unlike {@link WebhookUrlValidator}):
     * operators may legitimately host an internal mirror of the exit list. The URL is only
     * settable by {@code bruteForceLoginProtectionAdmin}, so the residual SSRF surface is accepted.
     */
    static void validateTorUrl(String url) {
        URI uri;
        try {
            uri = new URI(url);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Invalid Tor blocklist URL");
        }
        String scheme = uri.getScheme();
        if (scheme == null || !("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme))) {
            throw new IllegalArgumentException("Tor blocklist URL must use http or https");
        }
        if (uri.getUserInfo() != null) {
            throw new IllegalArgumentException("Tor blocklist URL must not contain user info");
        }
        if (StringUtils.isBlank(uri.getHost())) {
            throw new IllegalArgumentException("Tor blocklist URL must contain a host");
        }
    }

    /** Clamps the Tor list refresh interval to [{@code MIN_TOR_REFRESH_SEC}, {@code MAX_TOR_REFRESH_SEC}]. */
    static long clampTorRefreshSeconds(long seconds) {
        return Math.max(MIN_TOR_REFRESH_SEC, Math.min(MAX_TOR_REFRESH_SEC, seconds));
    }

    // Lenient address shape (not RFC-complete) — enough to reject obvious garbage while accepting
    // ordinary addresses. Used only as defense-in-depth on top of the control-char/CRLF rejection.
    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[^\\s@,]+@[^\\s@,]+\\.[^\\s@,]+$");

    /**
     * Rejects an email recipient that contains control characters / CRLF (which would otherwise be
     * persisted to the .cfg and enable SMTP header injection in {@code EmailBanAction}) or that is
     * not address-shaped. Supports a comma-separated list. Blank is allowed (clears the recipient).
     */
    private static void validateEmailRecipient(String recipient) {
        if (StringUtils.isBlank(recipient)) {
            return;
        }
        for (int i = 0; i < recipient.length(); i++) {
            char c = recipient.charAt(i);
            if (c < 0x20 || c == 0x7F) {
                throw new IllegalArgumentException("Email recipient contains control characters");
            }
        }
        for (String addr : recipient.split(",")) {
            String trimmed = addr.trim();
            if (!trimmed.isEmpty() && !EMAIL_PATTERN.matcher(trimmed).matches()) {
                throw new IllegalArgumentException("Invalid email recipient: " + AuditLogger.sanitize(trimmed));
            }
        }
    }

    /**
     * Tri-state webhook secret handling:
     * <ul>
     *   <li>{@code null} → keep existing dictionary entry untouched.</li>
     *   <li>{@code ""}   → remove the property from the dictionary (operator clear).</li>
     *   <li>non-empty   → encrypt with the {@code {enc}} marker and replace.</li>
     * </ul>
     * If an operator pasted plaintext into the .cfg, we also re-encrypt-in-place here so the next
     * persisted dictionary is encrypted.
     */
    private static void applyWebhookSecretUpdate(Dictionary<String, Object> props, String newSecret) {
        Object existing = props.get(GlobalConfigHolder.CFG_WEBHOOK_SECRET);
        if (newSecret == null) {
            // Unchanged from caller's POV. Opportunistically re-encrypt operator-pasted plaintext.
            if (existing != null && !WebhookSecretCodec.isEncrypted(String.valueOf(existing))) {
                try {
                    String reEncrypted = WebhookSecretCodec.encrypt(String.valueOf(existing));
                    if (reEncrypted != null) {
                        props.put(GlobalConfigHolder.CFG_WEBHOOK_SECRET, reEncrypted);
                    }
                } catch (IllegalStateException e) {
                    // Re-encryption is best-effort; skip silently so settings save still succeeds
                    LOGGER.warn("BFLP: opportunistic re-encryption of existing secret skipped: {}", e.getMessage());
                }
            }
            return;
        }
        if (newSecret.isEmpty()) {
            props.remove(GlobalConfigHolder.CFG_WEBHOOK_SECRET);
            return;
        }
        props.put(GlobalConfigHolder.CFG_WEBHOOK_SECRET, WebhookSecretCodec.encrypt(newSecret));
    }

    private static void applyNumericGlobalUpdate(Dictionary<String, Object> props, GlobalSettingsUpdate u) {
        if (u.getAuditLogMaxEntries() != null && u.getAuditLogMaxEntries() > 0) {
            int clamped = Math.max(AUDIT_LOG_MIN, Math.min(AUDIT_LOG_MAX, u.getAuditLogMaxEntries()));
            if (clamped != u.getAuditLogMaxEntries()) {
                LOGGER.info("BFLP: auditLogMaxEntries clamped from {} to {} (range [{}, {}])",
                        u.getAuditLogMaxEntries(), clamped, AUDIT_LOG_MIN, AUDIT_LOG_MAX);
            }
            props.put(GlobalConfigHolder.CFG_AUDIT_LOG_MAX, String.valueOf(clamped));
        }
        if (u.getRecidiveFactor() != null && u.getRecidiveFactor() >= 1.0) {
            props.put(GlobalConfigHolder.CFG_RECIDIVE_FACTOR, String.valueOf(u.getRecidiveFactor()));
        }
        if (u.getMaxBanTimeSeconds() != null && u.getMaxBanTimeSeconds() > 0) {
            props.put(GlobalConfigHolder.CFG_MAX_BAN_TIME_SEC, String.valueOf(u.getMaxBanTimeSeconds().longValue()));
        }
        if (u.getTorBlocklistRefreshSeconds() != null && u.getTorBlocklistRefreshSeconds() > 0) {
            long clamped = clampTorRefreshSeconds(u.getTorBlocklistRefreshSeconds());
            if (clamped != u.getTorBlocklistRefreshSeconds()) {
                LOGGER.info("BFLP: torBlocklistRefreshSeconds clamped from {} to {} (range [{}, {}])",
                        u.getTorBlocklistRefreshSeconds(), clamped, MIN_TOR_REFRESH_SEC, MAX_TOR_REFRESH_SEC);
            }
            props.put(GlobalConfigHolder.CFG_TOR_REFRESH_SEC, String.valueOf(clamped));
        }
    }

    private static String joinList(List<String> v) {
        return v == null ? "" : String.join(",", v);
    }

    // -------------------------------------------------------------------------------------------
    // Jail writes
    // -------------------------------------------------------------------------------------------

    public boolean saveJail(String name, Boolean enabled, Integer maxRetry, Integer findTimeSeconds, Integer banTimeSeconds) {
        if (StringUtils.isBlank(name) || JailConfigTracker.isUnsafeJailName(name)) {
            return false;
        }
        try {
            validateJailNumericFields(maxRetry, findTimeSeconds, banTimeSeconds);
        } catch (IllegalArgumentException ex) {
            LOGGER.warn("BFLP: rejected jail '{}' — {}", name, ex.getMessage());
            return false;
        }
        if (configurationAdmin == null) {
            LOGGER.error("BFLP: ConfigurationAdmin unavailable; cannot persist jail '{}'", name);
            return false;
        }
        try {
            Configuration cfg = findOrCreateJailConfig(name);
            Dictionary<String, Object> props = cfg.getProperties();
            if (props == null) {
                props = new Hashtable<>();
            }
            props.put(JailConfigTracker.CFG_NAME, name);
            if (enabled != null) {
                props.put(JailConfigTracker.CFG_ENABLED, String.valueOf(enabled));
            } else if (props.get(JailConfigTracker.CFG_ENABLED) == null) {
                props.put(JailConfigTracker.CFG_ENABLED, "true");
            }
            if (maxRetry != null && maxRetry > 0) {
                props.put(JailConfigTracker.CFG_MAX_RETRY, String.valueOf(maxRetry));
            }
            if (findTimeSeconds != null && findTimeSeconds > 0) {
                props.put(JailConfigTracker.CFG_FIND_TIME, String.valueOf(findTimeSeconds));
            }
            if (banTimeSeconds != null && banTimeSeconds > 0) {
                props.put(JailConfigTracker.CFG_BAN_TIME, String.valueOf(banTimeSeconds));
            }
            cfg.update(props);
            return true;
        } catch (IOException | InvalidSyntaxException e) {
            LOGGER.error("BFLP: error saving jail '{}'", AuditLogger.sanitize(name), e);
            return false;
        }
    }

    /**
     * Validates jail numeric fields against sane upper bounds before any I/O is attempted.
     * Throws {@link IllegalArgumentException} on the first out-of-range value found.
     */
    static void validateJailNumericFields(Integer maxRetry, Integer findTimeSeconds, Integer banTimeSeconds) {
        if (maxRetry != null && maxRetry > 0 && maxRetry > JAIL_MAX_RETRY_MAX) {
            throw new IllegalArgumentException("maxRetry exceeds maximum allowed value of " + JAIL_MAX_RETRY_MAX);
        }
        if (findTimeSeconds != null && findTimeSeconds > 0 && findTimeSeconds > JAIL_TIME_SECONDS_MAX) {
            throw new IllegalArgumentException("findTimeSeconds exceeds maximum allowed value of " + JAIL_TIME_SECONDS_MAX);
        }
        if (banTimeSeconds != null && banTimeSeconds > 0 && banTimeSeconds > JAIL_TIME_SECONDS_MAX) {
            throw new IllegalArgumentException("banTimeSeconds exceeds maximum allowed value of " + JAIL_TIME_SECONDS_MAX);
        }
    }

    public boolean deleteJail(String name) {
        if (StringUtils.isBlank(name) || JailConfigTracker.isUnsafeJailName(name)) {
            return false;
        }
        if (configurationAdmin == null) {
            return false;
        }
        try {
            Configuration cfg = findExistingJailConfig(name);
            if (cfg != null) {
                cfg.delete();
            }
            return true;
        } catch (IOException | InvalidSyntaxException e) {
            LOGGER.error("BFLP: error deleting jail '{}'", AuditLogger.sanitize(name), e);
            return false;
        }
    }

    private Configuration findOrCreateJailConfig(String name) throws IOException, InvalidSyntaxException {
        Configuration existing = findExistingJailConfig(name);
        if (existing != null) {
            return existing;
        }
        return configurationAdmin.createFactoryConfiguration(JailConfigTracker.FACTORY_PID, "?");
    }

    private Configuration findExistingJailConfig(String name) throws IOException, InvalidSyntaxException {
        String filter = "(&(service.factoryPid=" + JailConfigTracker.FACTORY_PID + ")(" + JailConfigTracker.CFG_NAME + "=" + escapeFilter(name) + "))";
        Configuration[] found = configurationAdmin.listConfigurations(filter);
        if (found != null && found.length > 0) {
            return found[0];
        }
        return null;
    }

    private static String escapeFilter(String s) {
        return s.replace("\\", "\\\\").replace("*", "\\*").replace("(", "\\(").replace(")", "\\)");
    }

    // -------------------------------------------------------------------------------------------
    // JCR bootstrap for ban + audit child containers (still JCR-backed runtime state).
    // -------------------------------------------------------------------------------------------

    /**
     * Ensures the {@code /settings/bruteforceloginprotection} parent node exists so that the
     * autocreated {@code bans} and {@code auditLog} child containers are available for
     * {@code BruteForceTracker} and {@link AuditLogger}. The global settings properties on this
     * node are no longer read — they live in OSGi config now — but the node itself is still the
     * JCR anchor for ban + audit children defined in the CND.
     */
    public JCRNodeWrapper getOrCreateSettingsNode(JCRSessionWrapper session) throws RepositoryException {
        JCRNodeWrapper node;
        boolean dirty = false;
        if (session.nodeExists(NODE_PATH)) {
            node = session.getNode(NODE_PATH);
        } else {
            JCRNodeWrapper settingsRoot = session.getNode(NODE_SETTINGS_PATH);
            node = settingsRoot.addNode(NODE_NAME, NT_SETTINGS);
            dirty = true;
        }
        // The CND declares bans + auditLog as autocreated, but Jackrabbit doesn't always
        // materialise autocreated typed children on addNode — observed in the deployed bundle as
        // PathNotFoundException on the very next session.getNode(BANS_NODE_PATH). Create them
        // explicitly so callers can address the paths immediately, then save once.
        if (!node.hasNode(BANS_NODE_NAME)) {
            node.addNode(BANS_NODE_NAME, NT_BANS_CONTAINER);
            dirty = true;
        }
        if (!node.hasNode(AUDIT_NODE_NAME)) {
            node.addNode(AUDIT_NODE_NAME, NT_AUDIT_CONTAINER);
            dirty = true;
        } else {
            // Upgrade path: containers created before jmix:autoSplitFolders was added to the CND
            // don't carry the mixin retroactively. Add it on the fly so auto-splitting takes
            // effect on the next addNode without forcing operators to drop /settings/...
            JCRNodeWrapper auditNode = node.getNode(AUDIT_NODE_NAME);
            if (!auditNode.isNodeType("jmix:autoSplitFolders")) {
                auditNode.addMixin("jmix:autoSplitFolders");
                dirty = true;
            }
        }
        if (dirty) {
            session.save();
        }
        return node;
    }

    public JCRTemplate getJcrTemplate() {
        return jcrTemplate;
    }
}
