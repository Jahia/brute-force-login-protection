package org.jahia.modules.bruteforceloginprotection.core;

import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.core.IMap;
import org.apache.commons.lang.StringUtils;
import org.jahia.api.Constants;
import org.jahia.modules.bruteforceloginprotection.BruteForceLoginProtectionConstants;
import org.jahia.modules.bruteforceloginprotection.CidrMatcher;
import org.jahia.modules.bruteforceloginprotection.hazelcast.HazelcastInstanceManager;
import org.jahia.modules.bruteforceloginprotection.spi.BanAction;
import org.jahia.modules.bruteforceloginprotection.spi.FailureEvent;
import org.jahia.modules.bruteforceloginprotection.spi.FailureRecorder;
import org.jahia.services.content.JCRNodeWrapper;
import org.jahia.services.content.JCRTemplate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.osgi.service.component.annotations.ReferencePolicyOption;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jcr.RepositoryException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import static org.jahia.modules.bruteforceloginprotection.BruteForceLoginProtectionConstants.*;

@Component(immediate = true, service = {BruteForceTracker.class, FailureRecorder.class})
public class BruteForceTracker implements FailureRecorder {

    private static final Logger LOGGER = LoggerFactory.getLogger(BruteForceTracker.class);

    @Reference
    private HazelcastInstanceManager hazelcastManager;

    @Reference
    private SettingsService settingsService;

    @Reference
    private AuditLogger auditLogger;

    @Reference
    private JCRTemplate jcrTemplate;

    private final List<BanAction> banActions = new CopyOnWriteArrayList<>();

    @Reference(service = BanAction.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            policyOption = ReferencePolicyOption.GREEDY,
            unbind = "removeBanAction")
    public void addBanAction(BanAction action) {
        banActions.add(action);
    }

    public void removeBanAction(BanAction action) {
        banActions.remove(action);
    }

    public List<BanAction> getBanActions() {
        List<BanAction> sorted = new ArrayList<>(banActions);
        sorted.sort((a, b) -> Integer.compare(a.priority(), b.priority()));
        return sorted;
    }

    @Override
    public void record(FailureEvent event) {
        if (event == null || event.getIp() == null) {
            return;
        }
        GlobalSettings settings = settingsService.getGlobalSettings();
        if (!settings.isActivated()) {
            return;
        }
        if (isWhitelisted(event.getIp(), settings.getWhitelistIps())) {
            return;
        }
        if (matchesIgnorePattern(event.getUsername(), settings.getIgnorePatterns())) {
            return;
        }

        JailConfig jail = settingsService.getJail(event.getJailName());
        if (jail == null || !jail.isEnabled()) {
            return;
        }

        HazelcastInstance hz = hazelcastInstance();
        if (hz == null) {
            LOGGER.debug("BFLP: hazelcast not running, skipping record");
            return;
        }

        long now = event.getTimestampMs() > 0 ? event.getTimestampMs() : System.currentTimeMillis();
        String key = event.getIp() + "|" + jail.getName();
        IMap<String, FailureWindow> windows = hz.getMap(MAP_WINDOWS);
        FailureWindow window = windows.get(key);
        if (window == null) {
            window = new FailureWindow(event.getIp(), jail.getName());
        }
        long cutoff = now - (jail.getFindTimeSec() * 1000L);
        window.prune(cutoff);
        window.add(now);

        auditLogger.log(AuditLogger.EVENT_FAILURE, event.getIp(), jail.getName(), event.getSourceName(),
                "username=" + AuditLogger.sanitize(event.getUsername()));

        if (window.size() >= jail.getMaxRetry()) {
            doBan(hz, event, jail, settings, now);
            windows.remove(key);
        } else {
            windows.put(key, window, jail.getFindTimeSec() * 2L, TimeUnit.SECONDS);
        }
    }

    private void doBan(HazelcastInstance hz, FailureEvent event, JailConfig jail, GlobalSettings settings, long now) {
        IMap<String, BannedIp> bans = hz.getMap(MAP_BANS);
        BannedIp existing = bans.get(event.getIp());
        int prevCount = 0;
        if (existing == null) {
            prevCount = readBanCountFromJcr(event.getIp());
        } else {
            prevCount = existing.getBanCount();
        }
        long banSec = RecidiveCalculator.next(prevCount, jail.getBanTimeSec(), settings.getRecidiveFactor(), settings.getMaxBanTimeSec());
        long bannedUntil = now + banSec * 1000L;
        String reason = "Exceeded " + jail.getMaxRetry() + " failures in " + jail.getFindTimeSec() + "s window";
        BannedIp banned = new BannedIp(event.getIp(), jail.getName(), event.getSourceName(),
                now, bannedUntil, prevCount + 1, reason);
        bans.put(event.getIp(), banned, banSec, TimeUnit.SECONDS);
        mirrorBanToJcr(banned);

        auditLogger.log(AuditLogger.EVENT_BAN, event.getIp(), jail.getName(), event.getSourceName(),
                "banCount=" + banned.getBanCount() + " durationSec=" + banSec);

        BanContext ctx = new BanContext(banned.getIp(), banned.getJailName(), banned.getSourceName(),
                banned.getBannedAt(), banned.getBannedUntil(), banned.getBanCount(), banned.getReason(),
                Collections.emptyMap());
        for (BanAction action : getBanActions()) {
            try {
                action.onBan(ctx);
            } catch (Exception e) {
                LOGGER.warn("BFLP: BanAction {} failed onBan: {}", action.getName(), e.getMessage());
            }
        }
    }

    public boolean banManually(String ip, String jailName, Integer durationSeconds, String reason) {
        if (StringUtils.isBlank(ip)) {
            return false;
        }
        HazelcastInstance hz = hazelcastInstance();
        if (hz == null) {
            return false;
        }
        GlobalSettings settings = settingsService.getGlobalSettings();
        String jName = StringUtils.isNotBlank(jailName) ? jailName : DEFAULT_JAIL_LOGIN;
        JailConfig jail = settingsService.getJail(jName);
        long now = System.currentTimeMillis();
        long banSec = (durationSeconds != null && durationSeconds > 0) ? durationSeconds : jail.getBanTimeSec();
        if (settings.getMaxBanTimeSec() > 0 && banSec > settings.getMaxBanTimeSec()) {
            banSec = settings.getMaxBanTimeSec();
        }
        IMap<String, BannedIp> bans = hz.getMap(MAP_BANS);
        BannedIp existing = bans.get(ip);
        int prevCount = existing != null ? existing.getBanCount() : readBanCountFromJcr(ip);
        BannedIp banned = new BannedIp(ip, jail.getName(), "manual", now, now + banSec * 1000L,
                prevCount + 1, StringUtils.defaultIfBlank(reason, "manual ban"));
        bans.put(ip, banned, banSec, TimeUnit.SECONDS);
        mirrorBanToJcr(banned);
        auditLogger.log(AuditLogger.EVENT_BAN, ip, jail.getName(), "manual",
                "manual ban for " + banSec + "s");
        BanContext ctx = new BanContext(ip, jail.getName(), "manual", now, banned.getBannedUntil(),
                banned.getBanCount(), banned.getReason(), Collections.emptyMap());
        for (BanAction action : getBanActions()) {
            try {
                action.onBan(ctx);
            } catch (Exception e) {
                LOGGER.warn("BFLP: BanAction {} failed onBan: {}", action.getName(), e.getMessage());
            }
        }
        return true;
    }

    public boolean unbanIp(String ip) {
        if (StringUtils.isBlank(ip)) {
            return false;
        }
        HazelcastInstance hz = hazelcastInstance();
        BannedIp removed = null;
        if (hz != null) {
            IMap<String, BannedIp> bans = hz.getMap(MAP_BANS);
            removed = bans.remove(ip);
        }
        removeBanFromJcr(ip);
        auditLogger.log(AuditLogger.EVENT_UNBAN, ip, removed != null ? removed.getJailName() : null,
                "manual", "manual unban");
        if (removed != null) {
            BanContext ctx = new BanContext(removed.getIp(), removed.getJailName(), removed.getSourceName(),
                    removed.getBannedAt(), removed.getBannedUntil(), removed.getBanCount(), removed.getReason(),
                    Collections.emptyMap());
            for (BanAction action : getBanActions()) {
                try {
                    action.onUnban(ctx);
                } catch (Exception e) {
                    LOGGER.warn("BFLP: BanAction {} failed onUnban: {}", action.getName(), e.getMessage());
                }
            }
        }
        return true;
    }

    public boolean flushAll() {
        HazelcastInstance hz = hazelcastInstance();
        if (hz != null) {
            hz.getMap(MAP_BANS).clear();
            hz.getMap(MAP_WINDOWS).clear();
            hz.getMap(MAP_NOTIFICATION_MARKERS).clear();
        }
        // also clear JCR ban mirrors
        try {
            jcrTemplate.doExecuteWithSystemSessionAsUser(null, Constants.EDIT_WORKSPACE, null, session -> {
                if (session.nodeExists(BANS_NODE_PATH)) {
                    JCRNodeWrapper bans = session.getNode(BANS_NODE_PATH);
                    javax.jcr.NodeIterator it = bans.getNodes();
                    while (it.hasNext()) {
                        it.nextNode().remove();
                    }
                    session.save();
                }
                return null;
            });
        } catch (RepositoryException e) {
            LOGGER.error("BFLP: failed clearing ban mirror", e);
        }
        return true;
    }

    @Override
    public boolean isIpCurrentlyBanned(String ip) {
        if (StringUtils.isBlank(ip)) {
            return false;
        }
        HazelcastInstance hz = hazelcastInstance();
        if (hz == null) {
            return false;
        }
        IMap<String, BannedIp> bans = hz.getMap(MAP_BANS);
        BannedIp banned = bans.get(ip);
        if (banned == null) {
            return false;
        }
        long now = System.currentTimeMillis();
        if (banned.isExpired(now)) {
            bans.remove(ip);
            removeBanFromJcr(ip);
            return false;
        }
        return true;
    }

    public Collection<BannedIp> listBans() {
        HazelcastInstance hz = hazelcastInstance();
        if (hz == null) {
            return Collections.emptyList();
        }
        return hz.<String, BannedIp>getMap(MAP_BANS).values();
    }

    public List<FailureWindow> listWindows() {
        HazelcastInstance hz = hazelcastInstance();
        if (hz == null) {
            return Collections.emptyList();
        }
        return new ArrayList<>(hz.<String, FailureWindow>getMap(MAP_WINDOWS).values());
    }

    private HazelcastInstance hazelcastInstance() {
        return hazelcastManager != null ? hazelcastManager.getHazelcastInstance() : null;
    }

    private static boolean isWhitelisted(String ip, String whitelist) {
        if (StringUtils.isBlank(whitelist)) {
            return false;
        }
        for (String entry : whitelist.split(",")) {
            String trimmed = StringUtils.trimToNull(entry);
            if (trimmed == null) continue;
            try {
                if (new CidrMatcher(trimmed).matches(ip)) {
                    return true;
                }
            } catch (IllegalArgumentException ignored) {
                // skip invalid CIDR
            }
        }
        return false;
    }

    private static boolean matchesIgnorePattern(String username, List<String> patterns) {
        if (username == null || patterns == null || patterns.isEmpty()) {
            return false;
        }
        for (String p : patterns) {
            if (StringUtils.isBlank(p)) continue;
            try {
                if (Pattern.compile(p).matcher(username).matches()) {
                    return true;
                }
            } catch (PatternSyntaxException e) {
                LOGGER.debug("BFLP: invalid ignore pattern '{}'", AuditLogger.sanitize(p));
            }
        }
        return false;
    }

    private int readBanCountFromJcr(String ip) {
        try {
            return jcrTemplate.doExecuteWithSystemSessionAsUser(null, Constants.EDIT_WORKSPACE, null, session -> {
                String name = ipToNodeName(ip);
                String path = BANS_NODE_PATH + "/" + name;
                if (!session.nodeExists(path)) {
                    return 0;
                }
                JCRNodeWrapper n = session.getNode(path);
                return n.hasProperty(PROP_BAN_COUNT) ? (int) n.getProperty(PROP_BAN_COUNT).getLong() : 0;
            });
        } catch (RepositoryException e) {
            return 0;
        }
    }

    private void mirrorBanToJcr(BannedIp banned) {
        try {
            jcrTemplate.doExecuteWithSystemSessionAsUser(null, Constants.EDIT_WORKSPACE, null, session -> {
                settingsService.getOrCreateSettingsNode(session);
                JCRNodeWrapper container = session.getNode(BANS_NODE_PATH);
                String name = ipToNodeName(banned.getIp());
                JCRNodeWrapper node = container.hasNode(name) ? container.getNode(name) : container.addNode(name, NT_BAN);
                node.setProperty(PROP_BAN_IP, banned.getIp());
                node.setProperty(PROP_BAN_JAIL, banned.getJailName());
                if (banned.getSourceName() != null) node.setProperty(PROP_BAN_SOURCE, banned.getSourceName());
                node.setProperty(PROP_BAN_AT, banned.getBannedAt());
                node.setProperty(PROP_BAN_UNTIL, banned.getBannedUntil());
                node.setProperty(PROP_BAN_COUNT, (long) banned.getBanCount());
                if (banned.getReason() != null) node.setProperty(PROP_BAN_REASON, banned.getReason());
                session.save();
                return null;
            });
        } catch (RepositoryException e) {
            LOGGER.warn("BFLP: failed to mirror ban to JCR for {}: {}", AuditLogger.sanitize(banned.getIp()), e.getMessage());
        }
    }

    public void removeBanFromJcr(String ip) {
        try {
            jcrTemplate.doExecuteWithSystemSessionAsUser(null, Constants.EDIT_WORKSPACE, null, session -> {
                String name = ipToNodeName(ip);
                String path = BANS_NODE_PATH + "/" + name;
                if (session.nodeExists(path)) {
                    session.getNode(path).remove();
                    session.save();
                }
                return null;
            });
        } catch (RepositoryException e) {
            LOGGER.debug("BFLP: failed to remove ban node for {}", AuditLogger.sanitize(ip));
        }
    }

    public static String ipToNodeName(String ip) {
        return "b-" + ip.replace('.', '_').replace(':', '-').replace('/', '_');
    }

    public Map<String, Object> getNotificationMarkersInfo() {
        HazelcastInstance hz = hazelcastInstance();
        if (hz == null) {
            return new HashMap<>();
        }
        return new HashMap<>(hz.<String, Object>getMap(MAP_NOTIFICATION_MARKERS));
    }

    // expose constant for callers
    public static final String CONST_REF = BruteForceLoginProtectionConstants.MAP_BANS;
}
