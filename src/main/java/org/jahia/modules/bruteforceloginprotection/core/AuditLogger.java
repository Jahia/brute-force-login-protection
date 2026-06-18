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
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;

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

    private static final DateTimeFormatter BUCKET_YEAR = DateTimeFormatter.ofPattern("yyyy");
    private static final DateTimeFormatter BUCKET_MONTH = DateTimeFormatter.ofPattern("MM");
    private static final DateTimeFormatter BUCKET_DAY = DateTimeFormatter.ofPattern("dd");

    /**
     * Piggyback trim: after this many writes have accumulated since the last trim, a trim is
     * triggered inline. This keeps the log bounded even if the periodic sweep in
     * {@link UnbanScheduler} fires infrequently, while avoiding an O(n) JCR scan on every write.
     */
    private static final long TRIM_WRITE_INTERVAL = 50;
    private final AtomicLong writesSinceTrim = new AtomicLong(0);

    public void log(String event, String ip, String jail, String source, String details) {
        try {
            jcrTemplate.doExecuteWithSystemSessionAsUser(null, Constants.EDIT_WORKSPACE, null, session -> {
                settingsService.getOrCreateSettingsNode(session);
                JCRNodeWrapper container = session.getNode(AUDIT_NODE_PATH);
                long now = System.currentTimeMillis();
                JCRNodeWrapper bucket = getOrCreateDateBucket(container, now);
                String name = "e-" + now + "-" + UUID.randomUUID().toString().substring(0, 8);
                JCRNodeWrapper entry = bucket.addNode(name, NT_AUDIT_ENTRY);
                entry.setProperty(PROP_AUDIT_TIMESTAMP, now);
                entry.setProperty(PROP_AUDIT_EVENT, event);
                // Sanitize ip, jail, and source at the JCR boundary to neutralise CR/LF/control
                // characters regardless of whether the caller already sanitized them. This mirrors
                // what callers already do for the 'details' field and closes the security boundary.
                if (ip != null) entry.setProperty(PROP_AUDIT_IP, sanitize(ip));
                if (jail != null) entry.setProperty(PROP_AUDIT_JAIL, sanitize(jail));
                if (source != null) entry.setProperty(PROP_AUDIT_SOURCE, sanitize(source));
                if (details != null) entry.setProperty(PROP_AUDIT_DETAILS, details);
                // First save: commits the new entry. This save is intentionally separate from
                // the second save inside trimIfNeeded so that the entry is persisted even when
                // the piggyback trim is not triggered.
                session.save();
                // Trim is deliberately NOT called here on every write (O(n) JCR scan).
                // The periodic sweep in UnbanScheduler calls trimAuditLog() every 30 s.
                // As a safety net, piggyback a trim every TRIM_WRITE_INTERVAL writes so the
                // log stays bounded even under high load between sweeps.
                // CAS the reset so a concurrent write's increment isn't lost between the
                // threshold check and the reset (which would delay the next piggyback trim).
                long writes = writesSinceTrim.incrementAndGet();
                if (writes >= TRIM_WRITE_INTERVAL && writesSinceTrim.compareAndSet(writes, 0)) {
                    // Second save (inside trimIfNeeded) commits only the node removals.
                    // The two saves are sequential on the same session and intentional:
                    // entry write → trimIfNeeded removals. No partial state is possible because
                    // each save is a complete atomic commit of its own pending changes.
                    trimIfNeeded(container);
                }
                return null;
            });
        } catch (RepositoryException e) {
            LOGGER.warn("BFLP: failed to write audit entry: {}", e.getMessage());
        }
    }

    /**
     * Public entry point for the periodic trim sweep called by {@link UnbanScheduler}.
     * Performs the O(n) full JCR scan only when invoked from the scheduler thread,
     * not on the hot per-login-failure write path.
     */
    public void trimAuditLog() {
        try {
            jcrTemplate.doExecuteWithSystemSessionAsUser(null, Constants.EDIT_WORKSPACE, null, session -> {
                if (!session.nodeExists(AUDIT_NODE_PATH)) {
                    return null;
                }
                JCRNodeWrapper container = session.getNode(AUDIT_NODE_PATH);
                trimIfNeeded(container);
                writesSinceTrim.set(0);
                return null;
            });
        } catch (RepositoryException e) {
            LOGGER.warn("BFLP: failed during periodic audit log trim: {}", e.getMessage());
        }
    }

    /**
     * Returns (creating if necessary) the {@code yyyy/MM/dd} folder under the audit container.
     * Mirrors the contract advertised by the {@code jmix:autoSplitFolders} mixin on the container
     * — we do it explicitly because Jahia's auto-split runtime is sensitive to how the parent was
     * looked up, and in this code path the children landed flat under the container despite the
     * mixin being correctly applied.
     */
    private static JCRNodeWrapper getOrCreateDateBucket(JCRNodeWrapper container, long epochMs) throws RepositoryException {
        ZonedDateTime now = ZonedDateTime.ofInstant(java.time.Instant.ofEpochMilli(epochMs), ZoneOffset.UTC);
        JCRNodeWrapper year = ensureFolder(container, BUCKET_YEAR.format(now));
        JCRNodeWrapper month = ensureFolder(year, BUCKET_MONTH.format(now));
        return ensureFolder(month, BUCKET_DAY.format(now));
    }

    private static JCRNodeWrapper ensureFolder(JCRNodeWrapper parent, String name) throws RepositoryException {
        // Buckets use the audit-log container type so the recursive wildcard
        // `+ * (jnt:bruteForceLoginProtectionAuditEntry)` allows AuditEntry children at every
        // level. jnt:contentFolder cannot host AuditEntry directly because jnt:content does not
        // extend nt:hierarchyNode (Jackrabbit rejects with "No child node definition").
        if (parent.hasNode(name)) {
            JCRNodeWrapper existing = parent.getNode(name);
            if (existing.isNodeType(NT_AUDIT_CONTAINER)) {
                return existing;
            }
            // Upgrade path: a previous version of this module created bucket folders as
            // jnt:contentFolder, which silently rejected AuditEntry children. Those folders are
            // empty (no entry ever wrote into them), so it's safe to drop and recreate.
            existing.remove();
        }
        return parent.addNode(name, NT_AUDIT_CONTAINER);
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
     * folders introduced by {@code jmix:autoSplitFolders} are traversed transparently.
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
        long toRemove = (long) nodes.size() - max;
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
