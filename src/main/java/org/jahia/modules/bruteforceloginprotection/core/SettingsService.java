package org.jahia.modules.bruteforceloginprotection.core;

import org.apache.commons.lang.StringUtils;
import org.jahia.modules.bruteforceloginprotection.actions.WebhookUrlValidator;
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
import java.util.Dictionary;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;

import static org.jahia.modules.bruteforceloginprotection.BruteForceLoginProtectionConstants.*;

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
            props.put(GlobalConfigHolder.CFG_EMAIL_RECIPIENT, u.getEmailRecipient());
        }
        if (u.getWebhookUrl() != null) {
            if (!u.getWebhookUrl().isEmpty()) {
                WebhookUrlValidator.validateUrl(u.getWebhookUrl());
            }
            props.put(GlobalConfigHolder.CFG_WEBHOOK_URL, u.getWebhookUrl());
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
            LOGGER.error("BFLP: error saving jail '{}'", sanitize(name), e);
            return false;
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
            LOGGER.error("BFLP: error deleting jail '{}'", sanitize(name), e);
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

    private static String sanitize(String s) {
        return s == null ? null : s.replaceAll("[\r\n]", "");
    }
}
