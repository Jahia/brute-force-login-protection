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
import org.osgi.service.component.annotations.Deactivate;
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
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import static org.jahia.modules.bruteforceloginprotection.BruteForceLoginProtectionConstants.*;

@Component(immediate = true, service = {BruteForceTracker.class, FailureRecorder.class})
public class BruteForceTracker implements FailureRecorder {

    private static final Logger LOGGER = LoggerFactory.getLogger(BruteForceTracker.class);
    private static final String SOURCE_MANUAL = "manual";
    private static final long IGNORE_PATTERN_MATCH_TIMEOUT_MS = 50L;
    private static final long IGNORE_PATTERN_WARN_THROTTLE_MS = 60_000L;
    // Bounded so a flood of failed logins carrying catastrophic usernames cannot exhaust threads.
    // Tasks are short-lived (50ms timeout + interruptible matching), so a small pool + queue is
    // ample; on saturation we abort and fail closed (see evaluateIgnorePattern).
    private static final int IGNORE_PATTERN_POOL_SIZE =
            Math.max(2, Runtime.getRuntime().availableProcessors());
    private static final int IGNORE_PATTERN_QUEUE_CAPACITY = 256;
    private static final ExecutorService IGNORE_PATTERN_EXECUTOR =
            new ThreadPoolExecutor(IGNORE_PATTERN_POOL_SIZE, IGNORE_PATTERN_POOL_SIZE,
                    30L, TimeUnit.SECONDS,
                    new LinkedBlockingQueue<>(IGNORE_PATTERN_QUEUE_CAPACITY),
                    r -> {
                        Thread t = new Thread(r, "bflp-regex-matcher");
                        t.setDaemon(true);
                        return t;
                    },
                    new ThreadPoolExecutor.AbortPolicy());
    static {
        ((ThreadPoolExecutor) IGNORE_PATTERN_EXECUTOR).allowCoreThreadTimeOut(true);
    }
    private static final AtomicLong lastIgnorePatternTimeoutWarnMs = new AtomicLong(0L);
    private static final AtomicLong lastHazelcastDownWarnMs = new AtomicLong(0L);

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

    @Deactivate
    public void deactivate() {
        IGNORE_PATTERN_EXECUTOR.shutdownNow();
    }

    public List<BanAction> getBanActions() {
        List<BanAction> sorted = new ArrayList<>(banActions);
        sorted.sort((a, b) -> Integer.compare(a.priority(), b.priority()));
        return sorted;
    }

    @Override
    public void recordEvent(FailureEvent event) {
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
        // The read-modify-write of the per-IP failure window must be atomic across the cluster:
        // without the per-key lock, two concurrent failures for the same IP can both read the same
        // window, mutate independent copies and write back, losing one increment (delayed/missed ban).
        // The lock scope is kept tight — audit logging and ban dispatch (which can do JCR/HTTP I/O)
        // run outside it so the key lock is never held across slow or external calls.
        boolean banTriggered = false;
        windows.lock(key);
        try {
            FailureWindow window = windows.get(key);
            if (window == null) {
                window = new FailureWindow(event.getIp(), jail.getName());
            }
            window.prune(now - (jail.getFindTimeSec() * 1000L));
            window.add(now);
            if (window.size() >= jail.getMaxRetry()) {
                banTriggered = true;
                windows.remove(key);
            } else {
                windows.put(key, window, jail.getFindTimeSec() * 2L, TimeUnit.SECONDS);
            }
        } finally {
            windows.unlock(key);
        }

        auditLogger.log(AuditLogger.EVENT_FAILURE, event.getIp(), jail.getName(), event.getSourceName(),
                "username=" + AuditLogger.sanitize(event.getUsername()));

        if (banTriggered) {
            doBan(hz, event, jail, settings, now);
        }
    }

    private static final int CAS_MAX_RETRIES = 5;

    private void doBan(HazelcastInstance hz, FailureEvent event, JailConfig jail, GlobalSettings settings, long now) {
        IMap<String, BannedIp> bans = hz.getMap(MAP_BANS);
        String ip = event.getIp();
        BannedIp banned = null;
        long banSec = 0L;
        // CAS loop: atomically compute the next ban from the current map state so concurrent
        // ban triggers on the same IP can't both observe banCount=N and both write N+1.
        for (int attempt = 0; attempt < CAS_MAX_RETRIES; attempt++) {
            BannedIp existing = bans.get(ip);
            int prevCount = (existing != null) ? existing.getBanCount() : readBanCountFromJcr(ip);
            banSec = RecidiveCalculator.next(prevCount, jail.getBanTimeSec(),
                    settings.getRecidiveFactor(), settings.getMaxBanTimeSec());
            long bannedUntil = now + banSec * 1000L;
            String reason = "Exceeded " + jail.getMaxRetry() + " failures in " + jail.getFindTimeSec() + "s window";
            BannedIp candidate = new BannedIp(ip, jail.getName(), event.getSourceName(),
                    now, bannedUntil, prevCount + 1, reason);
            boolean stored;
            if (existing == null) {
                stored = (bans.putIfAbsent(ip, candidate, banSec, TimeUnit.SECONDS) == null);
            } else {
                stored = bans.replace(ip, existing, candidate);
            }
            if (stored) {
                banned = candidate;
                break;
            }
        }
        if (banned == null) {
            if (LOGGER.isWarnEnabled()) {
                LOGGER.warn("BFLP: CAS exhaustion when updating ban for {} after {} retries; falling back to last-write-wins",
                        AuditLogger.sanitize(ip), CAS_MAX_RETRIES);
            }
            BannedIp existing = bans.get(ip);
            int prevCount = (existing != null) ? existing.getBanCount() : readBanCountFromJcr(ip);
            banSec = RecidiveCalculator.next(prevCount, jail.getBanTimeSec(),
                    settings.getRecidiveFactor(), settings.getMaxBanTimeSec());
            String reason = "Exceeded " + jail.getMaxRetry() + " failures in " + jail.getFindTimeSec() + "s window";
            banned = new BannedIp(ip, jail.getName(), event.getSourceName(),
                    now, now + banSec * 1000L, prevCount + 1, reason);
            bans.put(ip, banned, banSec, TimeUnit.SECONDS);
        }
        mirrorBanToJcr(banned);

        auditLogger.log(AuditLogger.EVENT_BAN, event.getIp(), jail.getName(), event.getSourceName(),
                "banCount=" + banned.getBanCount() + " durationSec=" + banSec);

        BanContext ctx = BanContext.builder()
                .ip(banned.getIp())
                .jailName(banned.getJailName())
                .sourceName(banned.getSourceName())
                .bannedAt(banned.getBannedAt())
                .bannedUntil(banned.getBannedUntil())
                .banCount(banned.getBanCount())
                .reason(banned.getReason())
                .build();
        dispatchOnBan(ctx);
    }

    private void dispatchOnBan(BanContext ctx) {
        for (BanAction action : getBanActions()) {
            try {
                action.onBan(ctx);
            } catch (Exception e) {
                LOGGER.warn("BFLP: BanAction {} failed onBan: {}", action.getName(), e.getMessage());
            }
        }
    }

    private void dispatchOnUnban(BanContext ctx) {
        for (BanAction action : getBanActions()) {
            try {
                action.onUnban(ctx);
            } catch (Exception e) {
                LOGGER.warn("BFLP: BanAction {} failed onUnban: {}", action.getName(), e.getMessage());
            }
        }
    }

    public boolean banManually(String ip, String jailName, Integer durationSeconds, String reason) {
        if (StringUtils.isBlank(ip) || !CidrMatcher.isIpLiteral(ip)) {
            // Manual bans (GraphQL/Karaf) must be IP literals: a hostname or garbage value would be
            // stored as a map/JCR key, could trigger DNS resolution on the ban-check path, and would
            // never match a real client address. Reject it at the boundary.
            LOGGER.warn("BFLP: refusing manual ban of non-IP value '{}'", AuditLogger.sanitize(ip));
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
        // Never store a zero/negative-duration ban (a misconfigured jail ban-time would otherwise
        // produce a ban that expires immediately and silently provides no protection).
        banSec = Math.max(1L, banSec);
        IMap<String, BannedIp> bans = hz.getMap(MAP_BANS);
        BannedIp existing = bans.get(ip);
        int prevCount = existing != null ? existing.getBanCount() : readBanCountFromJcr(ip);
        BannedIp banned = new BannedIp(ip, jail.getName(), SOURCE_MANUAL, now, now + banSec * 1000L,
                prevCount + 1, StringUtils.defaultIfBlank(reason, "manual ban"));
        bans.put(ip, banned, banSec, TimeUnit.SECONDS);
        mirrorBanToJcr(banned);
        auditLogger.log(AuditLogger.EVENT_BAN, ip, jail.getName(), SOURCE_MANUAL,
                "manual ban for " + banSec + "s");
        BanContext ctx = BanContext.builder()
                .ip(ip)
                .jailName(jail.getName())
                .sourceName(SOURCE_MANUAL)
                .bannedAt(now)
                .bannedUntil(banned.getBannedUntil())
                .banCount(banned.getBanCount())
                .reason(banned.getReason())
                .build();
        dispatchOnBan(ctx);
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
                SOURCE_MANUAL, "manual unban");
        if (removed != null) {
            BanContext ctx = BanContext.builder()
                    .ip(removed.getIp())
                    .jailName(removed.getJailName())
                    .sourceName(removed.getSourceName())
                    .bannedAt(removed.getBannedAt())
                    .bannedUntil(removed.getBannedUntil())
                    .banCount(removed.getBanCount())
                    .reason(removed.getReason())
                    .build();
            dispatchOnUnban(ctx);
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
        // Treat a missing OR not-running Hazelcast as "cannot enforce". This is the per-request
        // hot path, so we deliberately fail OPEN: blocking every login because the distributed
        // ban store is down would be a self-inflicted denial of service. We surface it with a
        // throttled WARN so operators notice the protection gap without flooding the log.
        if (hz == null || !hz.getLifecycleService().isRunning()) {
            long nowMs = System.currentTimeMillis();
            long last = lastHazelcastDownWarnMs.get();
            if (nowMs - last > IGNORE_PATTERN_WARN_THROTTLE_MS && lastHazelcastDownWarnMs.compareAndSet(last, nowMs)) {
                LOGGER.warn("BFLP: Hazelcast unavailable; ban enforcement temporarily disabled (fail-open)");
            }
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
            IgnorePatternResult result = evaluateIgnorePattern(username, p);
            if (result == IgnorePatternResult.MATCHED) {
                return true;
            }
            if (result == IgnorePatternResult.INTERRUPTED) {
                return false;
            }
        }
        return false;
    }

    private enum IgnorePatternResult { MATCHED, NOT_MATCHED, INTERRUPTED }

    private static IgnorePatternResult evaluateIgnorePattern(String username, String p) {
        if (StringUtils.isBlank(p)) {
            return IgnorePatternResult.NOT_MATCHED;
        }
        final Pattern compiled;
        try {
            compiled = Pattern.compile(p);
        } catch (PatternSyntaxException e) {
            LOGGER.debug("BFLP: invalid ignore pattern '{}'", AuditLogger.sanitize(p));
            return IgnorePatternResult.NOT_MATCHED;
        }
        final Future<Boolean> future;
        try {
            // Wrap the input so a cancel(true) interrupt actually aborts catastrophic backtracking:
            // Matcher polls charAt(), and InterruptibleCharSequence throws on an interrupted thread.
            future = IGNORE_PATTERN_EXECUTOR.submit(
                    () -> compiled.matcher(new InterruptibleCharSequence(username)).matches());
        } catch (RejectedExecutionException ree) {
            // Pool + queue saturated (likely a ReDoS-style flood). Fail closed, like a timeout.
            warnIgnorePatternTimeout(p);
            return IgnorePatternResult.MATCHED;
        }
        try {
            return Boolean.TRUE.equals(future.get(IGNORE_PATTERN_MATCH_TIMEOUT_MS, TimeUnit.MILLISECONDS))
                    ? IgnorePatternResult.MATCHED
                    : IgnorePatternResult.NOT_MATCHED;
        } catch (TimeoutException te) {
            future.cancel(true);
            warnIgnorePatternTimeout(p);
            // Fail closed: treat a timeout as a match so the failure is silently skipped
            // (denies an attacker who supplies a catastrophic username from bypassing
            // counter increments via a slow-regex pattern).
            return IgnorePatternResult.MATCHED;
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            future.cancel(true);
            return IgnorePatternResult.INTERRUPTED;
        } catch (Exception ex) {
            LOGGER.debug("BFLP: ignore-pattern '{}' threw {}",
                    AuditLogger.sanitize(p), ex.getClass().getSimpleName());
            return IgnorePatternResult.NOT_MATCHED;
        }
    }

    private static void warnIgnorePatternTimeout(String p) {
        long now = System.currentTimeMillis();
        long last = lastIgnorePatternTimeoutWarnMs.get();
        if (now - last > IGNORE_PATTERN_WARN_THROTTLE_MS
                && lastIgnorePatternTimeoutWarnMs.compareAndSet(last, now)
                && LOGGER.isWarnEnabled()) {
            LOGGER.warn("BFLP: ignore-pattern '{}' timed out after {}ms; treating as MATCHED to deny ReDoS bypass",
                    AuditLogger.sanitize(p), IGNORE_PATTERN_MATCH_TIMEOUT_MS);
        }
    }

    private int readBanCountFromJcr(String ip) {
        try {
            return jcrTemplate.doExecuteWithSystemSessionAsUser(null, Constants.EDIT_WORKSPACE, null, session -> {
                String name = ipToNodeName(ip);
                String path = String.join("/", BANS_NODE_PATH, name);
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
                node.setProperty(PROP_BAN_COUNT, banned.getBanCount());
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
                String path = String.join("/", BANS_NODE_PATH, name);
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

    /**
     * A {@link CharSequence} view that makes regex matching responsive to thread interruption.
     * {@link java.util.regex.Matcher} reads its input through {@code charAt}, so checking the
     * interrupt flag there lets a {@code future.cancel(true)} actually abort a catastrophic
     * backtracking match instead of leaving the worker thread spinning to completion.
     */
    /** Thrown by {@link InterruptibleCharSequence} to abort a regex match on thread interruption. */
    private static final class RegexInterruptedException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        RegexInterruptedException() {
            super("BFLP: regex matching interrupted");
        }
    }

    private static final class InterruptibleCharSequence implements CharSequence {
        private final CharSequence inner;

        InterruptibleCharSequence(CharSequence inner) {
            this.inner = inner;
        }

        @Override
        public char charAt(int index) {
            if (Thread.currentThread().isInterrupted()) {
                throw new RegexInterruptedException();
            }
            return inner.charAt(index);
        }

        @Override
        public int length() {
            return inner.length();
        }

        @Override
        public CharSequence subSequence(int start, int end) {
            return new InterruptibleCharSequence(inner.subSequence(start, end));
        }

        @Override
        public String toString() {
            return inner.toString();
        }
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
