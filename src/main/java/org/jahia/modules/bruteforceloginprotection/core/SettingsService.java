package org.jahia.modules.bruteforceloginprotection.core;

import org.apache.commons.lang.StringUtils;
import org.jahia.api.Constants;
import org.jahia.modules.bruteforceloginprotection.actions.WebhookUrlValidator;
import org.jahia.services.content.JCRCallback;
import org.jahia.services.content.JCRNodeWrapper;
import org.jahia.services.content.JCRSessionWrapper;
import org.jahia.services.content.JCRTemplate;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jcr.NodeIterator;
import javax.jcr.RepositoryException;
import javax.jcr.Value;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.jahia.modules.bruteforceloginprotection.BruteForceLoginProtectionConstants.*;

@Component(immediate = true, service = SettingsService.class)
public class SettingsService {

    private static final Logger LOGGER = LoggerFactory.getLogger(SettingsService.class);

    @Reference
    private JCRTemplate jcrTemplate;

    private final AtomicReference<GlobalSettings> cachedSettings = new AtomicReference<>();
    private final AtomicReference<Map<String, JailConfig>> cachedJails = new AtomicReference<>();

    @Activate
    public void start() {
        try {
            bootstrap();
        } catch (Exception e) {
            LOGGER.warn("BFLP: could not bootstrap settings node at activation: {}", e.getMessage());
        }
        invalidate();
    }

    public void invalidate() {
        cachedSettings.set(null);
        cachedJails.set(null);
    }

    public GlobalSettings getGlobalSettings() {
        GlobalSettings s = cachedSettings.get();
        if (s != null) {
            return s;
        }
        s = readGlobalSettings();
        cachedSettings.set(s);
        return s;
    }

    public Map<String, JailConfig> getJails() {
        Map<String, JailConfig> j = cachedJails.get();
        if (j != null) {
            return j;
        }
        j = readJails();
        cachedJails.set(j);
        return j;
    }

    public JailConfig getJail(String name) {
        if (name == null) {
            return null;
        }
        JailConfig jc = getJails().get(name);
        if (jc != null) {
            return jc;
        }
        // sensible defaults if not found
        return new JailConfig(name, true, DEFAULT_MAX_RETRY, DEFAULT_FIND_TIME_SEC, DEFAULT_BAN_TIME_SEC);
    }

    private GlobalSettings readGlobalSettings() {
        try {
            return jcrTemplate.doExecuteWithSystemSessionAsUser(null, Constants.EDIT_WORKSPACE, null,
                    (JCRCallback<GlobalSettings>) session -> {
                        if (!session.nodeExists(NODE_PATH)) {
                            return defaults();
                        }
                        JCRNodeWrapper node = session.getNode(NODE_PATH);
                        boolean activated = boolProp(node, PROP_ACTIVATED, false);
                        String whitelist = stringProp(node, PROP_WHITELIST_IPS, DEFAULT_WHITELIST);
                        List<String> ignore = stringArrayProp(node, PROP_IGNORE_PATTERNS);
                        boolean trustProxy = boolProp(node, PROP_TRUST_PROXY_HEADER, false);
                        List<String> trustedProxyCidrs = stringArrayProp(node, PROP_TRUSTED_PROXY_CIDRS);
                        boolean emailEnabled = boolProp(node, PROP_EMAIL_ENABLED, false);
                        String emailRecipient = stringProp(node, PROP_EMAIL_RECIPIENT, null);
                        String webhookUrl = stringProp(node, PROP_WEBHOOK_URL, null);
                        String webhookSecret = stringProp(node, PROP_WEBHOOK_SECRET, null);
                        int auditMax = (int) longProp(node, PROP_AUDIT_LOG_MAX, DEFAULT_AUDIT_LOG_MAX);
                        double recidive = doubleProp(node, PROP_RECIDIVE_FACTOR, DEFAULT_RECIDIVE_FACTOR);
                        long maxBan = longProp(node, PROP_MAX_BAN_TIME_SEC, DEFAULT_MAX_BAN_TIME_SEC);
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
                    });
        } catch (RepositoryException e) {
            LOGGER.error("BFLP: error reading global settings, returning defaults", e);
            return defaults();
        }
    }

    private Map<String, JailConfig> readJails() {
        try {
            return jcrTemplate.doExecuteWithSystemSessionAsUser(null, Constants.EDIT_WORKSPACE, null,
                    (JCRCallback<Map<String, JailConfig>>) session -> {
                        Map<String, JailConfig> map = new HashMap<>();
                        if (!session.nodeExists(JAILS_NODE_PATH)) {
                            map.put(DEFAULT_JAIL_LOGIN, new JailConfig(DEFAULT_JAIL_LOGIN, true,
                                    DEFAULT_MAX_RETRY, DEFAULT_FIND_TIME_SEC, DEFAULT_BAN_TIME_SEC));
                            return map;
                        }
                        JCRNodeWrapper jails = session.getNode(JAILS_NODE_PATH);
                        NodeIterator it = jails.getNodes();
                        while (it.hasNext()) {
                            JCRNodeWrapper n = (JCRNodeWrapper) it.nextNode();
                            String name = n.getName();
                            boolean enabled = boolProp(n, PROP_JAIL_ENABLED, true);
                            int maxRetry = (int) longProp(n, PROP_JAIL_MAX_RETRY, DEFAULT_MAX_RETRY);
                            long findTime = longProp(n, PROP_JAIL_FIND_TIME, DEFAULT_FIND_TIME_SEC);
                            long banTime = longProp(n, PROP_JAIL_BAN_TIME, DEFAULT_BAN_TIME_SEC);
                            map.put(name, new JailConfig(name, enabled, maxRetry, findTime, banTime));
                        }
                        if (map.isEmpty()) {
                            map.put(DEFAULT_JAIL_LOGIN, new JailConfig(DEFAULT_JAIL_LOGIN, true,
                                    DEFAULT_MAX_RETRY, DEFAULT_FIND_TIME_SEC, DEFAULT_BAN_TIME_SEC));
                        }
                        return map;
                    });
        } catch (RepositoryException e) {
            LOGGER.error("BFLP: error reading jails, returning default", e);
            Map<String, JailConfig> map = new HashMap<>();
            map.put(DEFAULT_JAIL_LOGIN, new JailConfig(DEFAULT_JAIL_LOGIN, true,
                    DEFAULT_MAX_RETRY, DEFAULT_FIND_TIME_SEC, DEFAULT_BAN_TIME_SEC));
            return map;
        }
    }

    public boolean saveGlobalSettings(GlobalSettingsUpdate update) {
        try {
            jcrTemplate.doExecuteWithSystemSessionAsUser(null, Constants.EDIT_WORKSPACE, null, session -> {
                JCRNodeWrapper node = getOrCreateSettingsNode(session);
                applyGlobalSettings(node, update);
                session.save();
                return null;
            });
            invalidate();
            return true;
        } catch (RepositoryException e) {
            LOGGER.error("BFLP: error saving global settings", e);
            return false;
        }
    }

    private static void applyGlobalSettings(JCRNodeWrapper node, GlobalSettingsUpdate u) throws RepositoryException {
        applySimpleProps(node, u);
        applyWebhookSecret(node, u.getWebhookSecret());
        applyNumericProps(node, u);
    }

    private static void applySimpleProps(JCRNodeWrapper node, GlobalSettingsUpdate u) throws RepositoryException {
        if (u.getActivated() != null) {
            node.setProperty(PROP_ACTIVATED, u.getActivated());
        }
        if (u.getWhitelistIps() != null) {
            node.setProperty(PROP_WHITELIST_IPS, u.getWhitelistIps());
        }
        if (u.getIgnorePatterns() != null) {
            for (String p : u.getIgnorePatterns()) {
                if (StringUtils.isNotBlank(p)) {
                    RegexSafetyCheck.assertSafe(p);
                }
            }
            node.setProperty(PROP_IGNORE_PATTERNS, u.getIgnorePatterns().toArray(new String[0]));
        }
        if (u.getTrustProxyHeader() != null) {
            node.setProperty(PROP_TRUST_PROXY_HEADER, u.getTrustProxyHeader());
        }
        if (u.getEmailEnabled() != null) {
            node.setProperty(PROP_EMAIL_ENABLED, u.getEmailEnabled());
        }
        if (u.getEmailRecipient() != null) {
            node.setProperty(PROP_EMAIL_RECIPIENT, u.getEmailRecipient());
        }
        if (u.getWebhookUrl() != null) {
            if (!u.getWebhookUrl().isEmpty()) {
                WebhookUrlValidator.validateUrl(u.getWebhookUrl());
            }
            node.setProperty(PROP_WEBHOOK_URL, u.getWebhookUrl());
        }
        if (u.getTrustedProxyCidrs() != null) {
            node.setProperty(PROP_TRUSTED_PROXY_CIDRS, u.getTrustedProxyCidrs().toArray(new String[0]));
        }
    }

    private static void applyWebhookSecret(JCRNodeWrapper node, String webhookSecret) throws RepositoryException {
        if (webhookSecret == null) {
            return;
        }
        if (webhookSecret.isEmpty()) {
            if (node.hasProperty(PROP_WEBHOOK_SECRET)) {
                node.getProperty(PROP_WEBHOOK_SECRET).remove();
            }
        } else {
            node.setProperty(PROP_WEBHOOK_SECRET, webhookSecret);
        }
    }

    private static final int AUDIT_LOG_MIN = 100;
    private static final int AUDIT_LOG_MAX = 100_000;

    private static void applyNumericProps(JCRNodeWrapper node, GlobalSettingsUpdate u) throws RepositoryException {
        if (u.getAuditLogMaxEntries() != null && u.getAuditLogMaxEntries() > 0) {
            int clamped = Math.max(AUDIT_LOG_MIN, Math.min(AUDIT_LOG_MAX, u.getAuditLogMaxEntries()));
            if (clamped != u.getAuditLogMaxEntries()) {
                LOGGER.info("BFLP: auditLogMaxEntries clamped from {} to {} (range [{}, {}])",
                        u.getAuditLogMaxEntries(), clamped, AUDIT_LOG_MIN, AUDIT_LOG_MAX);
            }
            node.setProperty(PROP_AUDIT_LOG_MAX, (long) clamped);
        }
        if (u.getRecidiveFactor() != null && u.getRecidiveFactor() >= 1.0) {
            node.setProperty(PROP_RECIDIVE_FACTOR, u.getRecidiveFactor());
        }
        if (u.getMaxBanTimeSeconds() != null && u.getMaxBanTimeSeconds() > 0) {
            node.setProperty(PROP_MAX_BAN_TIME_SEC, u.getMaxBanTimeSeconds().longValue());
        }
    }

    public boolean saveJail(String name, Boolean enabled, Integer maxRetry, Integer findTimeSeconds, Integer banTimeSeconds) {
        if (StringUtils.isBlank(name)) {
            return false;
        }
        try {
            jcrTemplate.doExecuteWithSystemSessionAsUser(null, Constants.EDIT_WORKSPACE, null, session -> {
                getOrCreateSettingsNode(session);
                JCRNodeWrapper jails = session.getNode(JAILS_NODE_PATH);
                JCRNodeWrapper jail = jails.hasNode(name) ? jails.getNode(name) : jails.addNode(name, NT_JAIL);
                if (enabled != null) {
                    jail.setProperty(PROP_JAIL_ENABLED, enabled);
                }
                if (maxRetry != null && maxRetry > 0) {
                    jail.setProperty(PROP_JAIL_MAX_RETRY, maxRetry.longValue());
                }
                if (findTimeSeconds != null && findTimeSeconds > 0) {
                    jail.setProperty(PROP_JAIL_FIND_TIME, findTimeSeconds.longValue());
                }
                if (banTimeSeconds != null && banTimeSeconds > 0) {
                    jail.setProperty(PROP_JAIL_BAN_TIME, banTimeSeconds.longValue());
                }
                session.save();
                return null;
            });
            invalidate();
            return true;
        } catch (RepositoryException e) {
            LOGGER.error("BFLP: error saving jail {}", sanitize(name), e);
            return false;
        }
    }

    public boolean deleteJail(String name) {
        if (StringUtils.isBlank(name)) {
            return false;
        }
        try {
            jcrTemplate.doExecuteWithSystemSessionAsUser(null, Constants.EDIT_WORKSPACE, null, session -> {
                if (session.nodeExists(JAILS_NODE_PATH + "/" + name)) {
                    session.getNode(JAILS_NODE_PATH + "/" + name).remove();
                    session.save();
                }
                return null;
            });
            invalidate();
            return true;
        } catch (RepositoryException e) {
            LOGGER.error("BFLP: error deleting jail {}", sanitize(name), e);
            return false;
        }
    }

    private void bootstrap() throws RepositoryException {
        jcrTemplate.doExecuteWithSystemSessionAsUser(null, Constants.EDIT_WORKSPACE, null, session -> {
            getOrCreateSettingsNode(session);
            // make sure default jail exists
            if (session.nodeExists(JAILS_NODE_PATH) && !session.nodeExists(JAILS_NODE_PATH + "/" + DEFAULT_JAIL_LOGIN)) {
                JCRNodeWrapper jails = session.getNode(JAILS_NODE_PATH);
                JCRNodeWrapper jail = jails.addNode(DEFAULT_JAIL_LOGIN, NT_JAIL);
                jail.setProperty(PROP_JAIL_ENABLED, true);
                jail.setProperty(PROP_JAIL_MAX_RETRY, DEFAULT_MAX_RETRY);
                jail.setProperty(PROP_JAIL_FIND_TIME, DEFAULT_FIND_TIME_SEC);
                jail.setProperty(PROP_JAIL_BAN_TIME, DEFAULT_BAN_TIME_SEC);
                session.save();
            }
            return null;
        });
    }

    public JCRNodeWrapper getOrCreateSettingsNode(JCRSessionWrapper session) throws RepositoryException {
        if (session.nodeExists(NODE_PATH)) {
            return session.getNode(NODE_PATH);
        }
        JCRNodeWrapper settingsRoot = session.getNode(NODE_SETTINGS_PATH);
        JCRNodeWrapper node = settingsRoot.addNode(NODE_NAME, NT_SETTINGS);
        node.setProperty(PROP_WHITELIST_IPS, DEFAULT_WHITELIST);
        node.setProperty(PROP_ACTIVATED, false);
        return node;
    }

    public JCRTemplate getJcrTemplate() {
        return jcrTemplate;
    }

    private static GlobalSettings defaults() {
        return GlobalSettings.builder()
                .activated(false)
                .whitelistIps(DEFAULT_WHITELIST)
                .ignorePatterns(Collections.emptyList())
                .trustProxyHeader(false)
                .emailEnabled(false)
                .auditLogMaxEntries(DEFAULT_AUDIT_LOG_MAX)
                .recidiveFactor(DEFAULT_RECIDIVE_FACTOR)
                .maxBanTimeSec(DEFAULT_MAX_BAN_TIME_SEC)
                .build();
    }

    private static boolean boolProp(JCRNodeWrapper n, String name, boolean def) throws RepositoryException {
        return n.hasProperty(name) ? n.getProperty(name).getBoolean() : def;
    }

    private static long longProp(JCRNodeWrapper n, String name, long def) throws RepositoryException {
        return n.hasProperty(name) ? n.getProperty(name).getLong() : def;
    }

    private static double doubleProp(JCRNodeWrapper n, String name, double def) throws RepositoryException {
        return n.hasProperty(name) ? n.getProperty(name).getDouble() : def;
    }

    private static String stringProp(JCRNodeWrapper n, String name, String def) throws RepositoryException {
        return n.hasProperty(name) ? n.getProperty(name).getString() : def;
    }

    private static List<String> stringArrayProp(JCRNodeWrapper n, String name) throws RepositoryException {
        if (!n.hasProperty(name)) {
            return Collections.emptyList();
        }
        Value[] values = n.getProperty(name).getValues();
        List<String> out = new ArrayList<>(values.length);
        for (Value v : values) {
            String s = v.getString();
            if (StringUtils.isNotBlank(s)) {
                out.add(s);
            }
        }
        return out;
    }

    private static String sanitize(String s) {
        return s == null ? null : s.replaceAll("[\r\n]", "");
    }
}
