package org.jahia.modules.bruteforceloginprotection.core;

import org.apache.commons.lang.StringUtils;
import org.jahia.api.Constants;
import org.jahia.services.content.JCRNodeWrapper;
import org.jahia.services.content.JCRTemplate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jcr.Node;
import javax.jcr.NodeIterator;
import javax.jcr.RepositoryException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.jahia.modules.bruteforceloginprotection.BruteForceLoginProtectionConstants.*;

@Component(immediate = true, service = AuditLogger.class)
public class AuditLogger {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuditLogger.class);

    public static final String EVENT_BAN = "BAN";
    public static final String EVENT_UNBAN = "UNBAN";
    public static final String EVENT_FAILURE = "FAILURE";
    public static final String EVENT_CONFIG_CHANGE = "CONFIG_CHANGE";

    @Reference
    private JCRTemplate jcrTemplate;

    @Reference
    private SettingsService settingsService;

    public void log(String event, String ip, String jail, String source, String details) {
        try {
            jcrTemplate.doExecuteWithSystemSessionAsUser(null, Constants.EDIT_WORKSPACE, null, session -> {
                settingsService.getOrCreateSettingsNode(session);
                JCRNodeWrapper container = session.getNode(AUDIT_NODE_PATH);
                String name = "e-" + System.currentTimeMillis() + "-" + UUID.randomUUID().toString().substring(0, 8);
                JCRNodeWrapper entry = container.addNode(name, NT_AUDIT_ENTRY);
                entry.setProperty(PROP_AUDIT_TIMESTAMP, System.currentTimeMillis());
                entry.setProperty(PROP_AUDIT_EVENT, event);
                if (ip != null) entry.setProperty(PROP_AUDIT_IP, ip);
                if (jail != null) entry.setProperty(PROP_AUDIT_JAIL, jail);
                if (source != null) entry.setProperty(PROP_AUDIT_SOURCE, source);
                if (details != null) entry.setProperty(PROP_AUDIT_DETAILS, details);
                session.save();
                trimIfNeeded(container);
                return null;
            });
        } catch (RepositoryException e) {
            LOGGER.warn("BFLP: failed to write audit entry: {}", e.getMessage());
        }
    }

    public List<AuditEntry> list(int limit) {
        try {
            return jcrTemplate.doExecuteWithSystemSessionAsUser(null, Constants.EDIT_WORKSPACE, null, session -> {
                if (!session.nodeExists(AUDIT_NODE_PATH)) {
                    return new ArrayList<>();
                }
                List<AuditEntry> out = readAllEntries(session.getNode(AUDIT_NODE_PATH));
                out.sort((a, b) -> Long.compare(b.getTimestamp(), a.getTimestamp()));
                return applyLimit(out, limit);
            });
        } catch (RepositoryException e) {
            LOGGER.error("BFLP: failed to list audit entries", e);
            return new ArrayList<>();
        }
    }

    private static List<AuditEntry> readAllEntries(JCRNodeWrapper container) throws RepositoryException {
        List<Node> nodes = new ArrayList<>();
        collectEntryNodes(container, nodes);
        List<AuditEntry> out = new ArrayList<>(nodes.size());
        for (Node n : nodes) {
            out.add(toEntry(n));
        }
        return out;
    }

    /**
     * Walks the audit container recursively, collecting nodes that represent audit entries
     * (identified by the presence of the timestamp property). Intermediate {@code yyyy/MM/dd}
     * folders introduced by {@code jmix:autoSplitFolder} are traversed transparently.
     */
    private static void collectEntryNodes(Node parent, List<Node> out) throws RepositoryException {
        NodeIterator it = parent.getNodes();
        while (it.hasNext()) {
            Node child = it.nextNode();
            if (child.hasProperty(PROP_AUDIT_TIMESTAMP)) {
                out.add(child);
            } else {
                collectEntryNodes(child, out);
            }
        }
    }

    private static AuditEntry toEntry(Node n) throws RepositoryException {
        AuditEntry e = new AuditEntry();
        e.setId(n.getName());
        if (n.hasProperty(PROP_AUDIT_TIMESTAMP)) e.setTimestamp(n.getProperty(PROP_AUDIT_TIMESTAMP).getLong());
        if (n.hasProperty(PROP_AUDIT_EVENT)) e.setEvent(n.getProperty(PROP_AUDIT_EVENT).getString());
        if (n.hasProperty(PROP_AUDIT_IP)) e.setIp(n.getProperty(PROP_AUDIT_IP).getString());
        if (n.hasProperty(PROP_AUDIT_JAIL)) e.setJail(n.getProperty(PROP_AUDIT_JAIL).getString());
        if (n.hasProperty(PROP_AUDIT_SOURCE)) e.setSource(n.getProperty(PROP_AUDIT_SOURCE).getString());
        if (n.hasProperty(PROP_AUDIT_DETAILS)) e.setDetails(n.getProperty(PROP_AUDIT_DETAILS).getString());
        return e;
    }

    private static List<AuditEntry> applyLimit(List<AuditEntry> entries, int limit) {
        if (limit > 0 && entries.size() > limit) {
            return new ArrayList<>(entries.subList(0, limit));
        }
        return entries;
    }

    public boolean clear() {
        try {
            jcrTemplate.doExecuteWithSystemSessionAsUser(null, Constants.EDIT_WORKSPACE, null, session -> {
                if (session.nodeExists(AUDIT_NODE_PATH)) {
                    JCRNodeWrapper container = session.getNode(AUDIT_NODE_PATH);
                    NodeIterator it = container.getNodes();
                    while (it.hasNext()) {
                        it.nextNode().remove();
                    }
                    session.save();
                }
                return null;
            });
            return true;
        } catch (RepositoryException e) {
            LOGGER.error("BFLP: failed to clear audit log", e);
            return false;
        }
    }

    private void trimIfNeeded(JCRNodeWrapper container) throws RepositoryException {
        int max = settingsService.getGlobalSettings().getAuditLogMaxEntries();
        if (max <= 0) {
            return;
        }
        List<Node> nodes = new ArrayList<>();
        collectEntryNodes(container, nodes);
        if (nodes.size() <= max) {
            return;
        }
        long toRemove = nodes.size() - max;
        nodes.sort((a, b) -> {
            try {
                long ta = a.hasProperty(PROP_AUDIT_TIMESTAMP) ? a.getProperty(PROP_AUDIT_TIMESTAMP).getLong() : 0L;
                long tb = b.hasProperty(PROP_AUDIT_TIMESTAMP) ? b.getProperty(PROP_AUDIT_TIMESTAMP).getLong() : 0L;
                return Long.compare(ta, tb);
            } catch (RepositoryException e) {
                return 0;
            }
        });
        for (int i = 0; i < toRemove && i < nodes.size(); i++) {
            nodes.get(i).remove();
        }
        container.getSession().save();
    }

    public static String sanitize(String s) {
        return s == null ? null : StringUtils.replaceEach(s, new String[]{"\r", "\n"}, new String[]{"", ""});
    }

    public static class AuditEntry {
        private String id;
        private long timestamp;
        private String event;
        private String ip;
        private String jail;
        private String source;
        private String details;
        public String getId() { return id; }
        public void setId(String id) { this.id = id; }
        public long getTimestamp() { return timestamp; }
        public void setTimestamp(long timestamp) { this.timestamp = timestamp; }
        public String getEvent() { return event; }
        public void setEvent(String event) { this.event = event; }
        public String getIp() { return ip; }
        public void setIp(String ip) { this.ip = ip; }
        public String getJail() { return jail; }
        public void setJail(String jail) { this.jail = jail; }
        public String getSource() { return source; }
        public void setSource(String source) { this.source = source; }
        public String getDetails() { return details; }
        public void setDetails(String details) { this.details = details; }
    }
}
