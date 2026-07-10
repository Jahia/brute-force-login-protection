package org.jahia.community.bruteforceloginprotection.core;

import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.core.IMap;
import org.apache.commons.lang.StringUtils;
import org.jahia.api.Constants;
import org.jahia.community.bruteforceloginprotection.CidrListCache;
import org.jahia.community.bruteforceloginprotection.CidrMatcher;
import org.jahia.community.bruteforceloginprotection.hazelcast.HazelcastInstanceManager;
import org.jahia.community.bruteforceloginprotection.spi.BanAction;
import org.jahia.community.bruteforceloginprotection.spi.FailureEvent;
import org.jahia.community.bruteforceloginprotection.spi.FailureRecorder;
import org.jahia.services.content.JCRNodeWrapper;
import org.jahia.services.content.JCRSessionWrapper;
import org.jahia.services.content.JCRTemplate;
import org.osgi.service.component.annotations.Activate;
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
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import static org.jahia.community.bruteforceloginprotection.BruteForceLoginProtectionConstants.*;

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

    // Created in @Activate and shut down in @Deactivate so a bundle refresh never leaves
    // submissions hitting a terminated pool (which would fail-closed and silently skip all
    // ignore patterns). Instance state, not static, so the lifecycle is bound to the component.
    private ExecutorService ignorePatternExecutor;
    private final AtomicLong lastIgnorePatternTimeoutWarnMs = new AtomicLong(0L);
    // Throttles the fail-open ERROR alert emitted when Hazelcast is unavailable (gates an ERROR, not a WARN).
    private final AtomicLong lastHazelcastDownAlertMs = new AtomicLong(0L);

    // Cache compiled Pattern objects so each distinct pattern string is compiled once rather
    // than on every login attempt. PatternSyntaxException entries are never cached (the compile
    // call is simply skipped and NOT_MATCHED is returned, exactly as before).
    // Operator-configured patterns are typically few; 256 is a generous ceiling. When the cap is
    // reached the whole cache is cleared (coarse but safe — entries are recompiled on next use).
    private static final int MAX_COMPILED_PATTERN_CACHE = 256;
    private final ConcurrentHashMap<String, Pattern> compiledPatternCache = new ConcurrentHashMap<>();

    // Cache for the parsed whitelist CidrMatcher list. Recomputed only when the whitelist
    // settings string changes; avoids constructing a new CidrMatcher per entry on every request.
    private final CidrListCache whitelistCache = new CidrListCache();

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

    @Activate
    public void activate() {
        ThreadPoolExecutor exec = new ThreadPoolExecutor(IGNORE_PATTERN_POOL_SIZE, IGNORE_PATTERN_POOL_SIZE,
                30L, TimeUnit.SECONDS,
                new LinkedBlockingQueue<>(IGNORE_PATTERN_QUEUE_CAPACITY),
                r -> {
                    Thread t = new Thread(r, "bflp-regex-matcher");
                    t.setDaemon(true);
                    return t;
                },
                new ThreadPoolExecutor.AbortPolicy());
        exec.allowCoreThreadTimeOut(true);
        this.ignorePatternExecutor = exec;
        reconcileJcrBansOnStartup();
    }

    @Deactivate
    public void deactivate() {
        if (ignorePatternExecutor != null) {
            // Give in-flight (interruptible, <=50ms) matches a brief grace period before forcing
            // shutdown, mirroring WebhookBanAction.deactivate for consistency.
            ignorePatternExecutor.shutdown();
            try {
                if (!ignorePatternExecutor.awaitTermination(100L, TimeUnit.MILLISECONDS)) {
                    ignorePatternExecutor.shutdownNow();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                ignorePatternExecutor.shutdownNow();
            }
        }
    }

    /**
     * Startup reconciliation between the (authoritative) Hazelcast ban map and the best-effort JCR
     * mirror. JCR ban nodes whose {@code banned_until} is already in the past are dropped rather
     * than left to be resurrected as active bans; live bans whose Hazelcast TTL did not survive a
     * full cluster restart are restored into the map. Best-effort: any failure is logged and
     * swallowed so a JCR hiccup never blocks component activation.
     */
    private void reconcileJcrBansOnStartup() {
        HazelcastInstance hz = hazelcastInstance();
        if (hz == null || !hz.getLifecycleService().isRunning()) {
            // Without a running Hazelcast we can neither restore live bans nor safely decide which
            // JCR mirrors are stale. Do NOT mutate JCR here: deleting nodes now would permanently
            // lose live bans (the in-memory map can't be repopulated). Bail out so a later
            // reconciliation (once Hazelcast is up) can do the full job.
            LOGGER.warn("BFLP: Hazelcast not running at startup; skipping JCR ban reconciliation (will be reconciled later)");
            return;
        }
        IMap<String, BannedIp> bans = hz.getMap(MAP_BANS);
        try {
            jcrTemplate.doExecuteWithSystemSessionAsUser(null, Constants.EDIT_WORKSPACE, null, session -> {
                reconcileBansInSession(session, bans);
                return null;
            });
        } catch (RepositoryException | RuntimeException e) {
            // A broad catch here is deliberate so that a reconciliation failure can never escape
            // component activation. Any JCR or runtime error is logged and then intentionally ignored.
            LOGGER.warn("BFLP: startup ban reconciliation failed: {}", e.getMessage());
        }
    }

    /** Package-private (rather than private) so it is directly unit-testable without needing a
     * full component activation cycle or reflection — behavior is otherwise unchanged (F10). */
    static void reconcileBansInSession(JCRSessionWrapper session, IMap<String, BannedIp> bans)
            throws RepositoryException {
        if (!session.nodeExists(BANS_NODE_PATH)) {
            return;
        }
        long now = System.currentTimeMillis();
        javax.jcr.NodeIterator it = session.getNode(BANS_NODE_PATH).getNodes();
        // Collect stale nodes first; removing while iterating the live NodeIterator can
        // corrupt iteration. We delete them only after the iterator is exhausted.
        List<JCRNodeWrapper> stale = new ArrayList<>();
        while (it.hasNext()) {
            JCRNodeWrapper node = (JCRNodeWrapper) it.nextNode();
            long until = node.hasProperty(PROP_BAN_UNTIL) ? node.getProperty(PROP_BAN_UNTIL).getLong() : 0L;
            if (until > 0 && until <= now) {
                // Stale: TTL already elapsed. Drop it so it is not rehydrated as active.
                stale.add(node);
            } else {
                // Live ban: restore into the in-memory map if it didn't survive restart.
                restoreLiveBan(bans, node, until, now);
            }
        }
        removeStaleNodes(session, stale);
    }

    private static void removeStaleNodes(JCRSessionWrapper session, List<JCRNodeWrapper> stale)
            throws RepositoryException {
        if (stale.isEmpty()) {
            return;
        }
        for (JCRNodeWrapper node : stale) {
            node.remove();
        }
        session.save();
    }

    private static void restoreLiveBan(IMap<String, BannedIp> bans, JCRNodeWrapper node, long until, long now)
            throws RepositoryException {
        String ip = node.hasProperty(PROP_BAN_IP) ? node.getProperty(PROP_BAN_IP).getString() : null;
        if (ip == null || bans.containsKey(ip)) {
            return;
        }
        BannedIp restored = new BannedIp(ip,
                node.hasProperty(PROP_BAN_JAIL) ? node.getProperty(PROP_BAN_JAIL).getString() : null,
                node.hasProperty(PROP_BAN_SOURCE) ? node.getProperty(PROP_BAN_SOURCE).getString() : null,
                node.hasProperty(PROP_BAN_AT) ? node.getProperty(PROP_BAN_AT).getLong() : now,
                until,
                node.hasProperty(PROP_BAN_COUNT) ? (int) node.getProperty(PROP_BAN_COUNT).getLong() : 1,
                node.hasProperty(PROP_BAN_REASON) ? node.getProperty(PROP_BAN_REASON).getString() : null);
        long ttlSec = Math.max(1L, (until - now) / 1000L);
        bans.putIfAbsent(ip, restored, ttlSec, TimeUnit.SECONDS);
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
        // Read the JCR-mirrored ban count once: it only matters when the in-memory entry is absent,
        // and re-reading it inside the CAS loop would issue a JCR read per retry on the hot path.
        int jcrBanCount = readBanCountFromJcr(ip);
        // CAS loop: atomically compute the next ban from the current map state so concurrent
        // ban triggers on the same IP can't both observe banCount=N and both write N+1.
        for (int attempt = 0; attempt < CAS_MAX_RETRIES; attempt++) {
            BannedIp existing = bans.get(ip);
            int prevCount = (existing != null) ? existing.getBanCount() : jcrBanCount;
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
            // Re-read the recidive base here rather than reusing the pre-loop jcrBanCount: after a
            // full CAS exhaustion the map state has changed, so the pre-loop value may be stale and
            // would under-count the recidive escalation.
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
            if (LOGGER.isWarnEnabled()) {
                LOGGER.warn("BFLP: refusing manual ban of non-IP value '{}'", AuditLogger.sanitize(ip));
            }
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
            long last = lastHazelcastDownAlertMs.get();
            if (nowMs - last > IGNORE_PATTERN_WARN_THROTTLE_MS && lastHazelcastDownAlertMs.compareAndSet(last, nowMs)) {
                // Alertable ERROR: while the distributed ban store is down, NO ban is enforced
                // (fail-open). Operators must treat this as a protection outage, not noise.
                LOGGER.error("BFLP: Hazelcast unavailable; ban enforcement DISABLED cluster-wide (fail-open) - all logins permitted until it recovers");
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
            // Value-checked remove: only act if this request actually removed *this* exact entry.
            // A plain remove(ip) could evict a concurrently re-installed fresh ban; using the
            // value-checked overload ensures we only touch JCR when we removed the stale entry.
            // The UnbanScheduler sweep is the primary cleanup path; this is a backstop.
            if (bans.remove(ip, banned)) {
                removeBanFromJcr(ip);
            }
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

    private boolean isWhitelisted(String ip, String whitelist) {
        return whitelistCache.matchesAny(ip, whitelist);
    }

    private boolean matchesIgnorePattern(String rawUsername, List<String> patterns) {
        if (rawUsername == null || patterns == null || patterns.isEmpty()) {
            return false;
        }
        // Normalize ONLY for matching (trim + lower-case), consistently for every auth method, so
        // case/whitespace variants of an allowlisted account ("Admin", " admin ") cannot bypass an
        // operator's ignorePatterns. The original-case username is still recorded in the audit log.
        String username = rawUsername.trim().toLowerCase(java.util.Locale.ROOT);
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

    private IgnorePatternResult evaluateIgnorePattern(String username, String p) {
        if (StringUtils.isBlank(p)) {
            return IgnorePatternResult.NOT_MATCHED;
        }
        Pattern compiled = compiledPattern(p);
        if (compiled == null) {
            return IgnorePatternResult.NOT_MATCHED;
        }
        Future<Boolean> future = submitMatchTask(compiled, username, p);
        if (future == null) {
            return IgnorePatternResult.NOT_MATCHED;
        }
        return awaitMatchResult(future, p);
    }

    /**
     * Returns a compiled {@link Pattern} for {@code p}, using the cache so each distinct
     * pattern string is only compiled once. Returns {@code null} for invalid patterns
     * (PatternSyntaxException), which the caller treats as NOT_MATCHED.
     */
    private Pattern compiledPattern(String p) {
        Pattern cached = compiledPatternCache.get(p);
        if (cached != null) {
            return cached;
        }
        try {
            Pattern compiled = Pattern.compile(p);
            if (compiledPatternCache.size() >= MAX_COMPILED_PATTERN_CACHE) {
                compiledPatternCache.clear();
            }
            compiledPatternCache.putIfAbsent(p, compiled);
            return compiledPatternCache.get(p);
        } catch (PatternSyntaxException e) {
            LOGGER.debug("BFLP: invalid ignore pattern '{}'", AuditLogger.sanitize(p));
            return null;
        }
    }

    /**
     * Submits the match task to the bounded executor. Returns {@code null} when the executor
     * is shut down (fail-open: NOT_MATCHED) or when the queue is saturated (fail-closed via
     * {@link #warnIgnorePatternTimeout} before returning MATCHED — handled by the non-null
     * sentinel return so the caller can distinguish the two cases).
     *
     * Returns a non-null Future on success, or null to signal NOT_MATCHED (executor gone).
     * Fail-closed (queue saturated) is surfaced by warning and returning a special sentinel;
     * to keep the method simple it instead calls warnIgnorePatternTimeout and returns null,
     * with the caller treating null as NOT_MATCHED — but pool saturation must be fail-closed.
     * Therefore this method returns a completed MATCHED future on saturation so the
     * awaitMatchResult path can handle it uniformly.
     */
    private Future<Boolean> submitMatchTask(Pattern compiled, String username, String p) {
        // During/after @Deactivate the executor is shut down. Fail OPEN so failure recording
        // is not silently suppressed when the component is torn down.
        if (ignorePatternExecutor == null || ignorePatternExecutor.isShutdown()) {
            return null;
        }
        try {
            // Wrap the input so cancel(true) actually aborts catastrophic backtracking:
            // Matcher polls charAt(), and InterruptibleCharSequence throws on interrupted thread.
            return ignorePatternExecutor.submit(
                    () -> compiled.matcher(new InterruptibleCharSequence(username)).matches());
        } catch (RejectedExecutionException ree) {
            // Pool + queue saturated (likely a ReDoS-style flood). Fail closed, like a timeout.
            warnIgnorePatternTimeout(p);
            return java.util.concurrent.CompletableFuture.completedFuture(Boolean.TRUE);
        }
    }

    /**
     * Waits for the match future and maps the outcome to an {@link IgnorePatternResult}.
     * Timeout and thread-interruption semantics are unchanged from the original implementation.
     */
    private IgnorePatternResult awaitMatchResult(Future<Boolean> future, String p) {
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

    private void warnIgnorePatternTimeout(String p) {
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

    static String ipToNodeName(String ip) {
        return "b-" + ip.replace('.', '_').replace(':', '-').replace('/', '_');
    }

    /** Thrown by {@link InterruptibleCharSequence} to abort a regex match on thread interruption. */
    private static final class RegexInterruptedException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        RegexInterruptedException() {
            super("BFLP: regex matching interrupted");
        }
    }

    /**
     * A {@link CharSequence} view that makes regex matching responsive to thread interruption.
     * {@link java.util.regex.Matcher} reads its input through {@code charAt}, so checking the
     * interrupt flag there lets a {@code future.cancel(true)} actually abort a catastrophic
     * backtracking match instead of leaving the worker thread spinning to completion.
     */
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
}
