package org.jahia.community.bruteforceloginprotection.core;

import org.apache.commons.lang.StringUtils;
import org.jahia.community.bruteforceloginprotection.CidrListCache;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;

/**
 * Single decision point for the proactive IP blocklist enforced at the auth valve:
 * a static operator-configured CIDR list plus the dynamic Tor exit-address list
 * ({@link TorExitNodeFetcher}).
 *
 * <p>Decision order in {@link #getBlockReason(String)}: module {@code activated} flag →
 * whitelist (always wins — the self-lockout safety valve) → static blocklist → Tor list.
 * Everything is served from per-node in-memory state, so blocklist enforcement keeps working
 * even while Hazelcast is unavailable (unlike bans, see ADR 0002).</p>
 *
 * <p>{@link #onBlocked(String, String)} logs every hit at INFO but writes at most one
 * {@code BLOCKED} audit entry per IP per hour: Tor scanners can hammer a login page, and an
 * unthrottled audit trail would flood the JCR audit log.</p>
 */
@Component(immediate = true, service = BlocklistService.class)
public class BlocklistService {

    private static final Logger LOGGER = LoggerFactory.getLogger(BlocklistService.class);

    public static final String REASON_STATIC = "static-blocklist";
    public static final String REASON_TOR = "tor-exit";

    static final long AUDIT_THROTTLE_MS = 60L * 60 * 1000;      // one audit entry per IP per hour
    static final int THROTTLE_PRUNE_THRESHOLD = 10_000;         // start pruning stale entries past this size
    static final int THROTTLE_HARD_CAP = 20_000;                // absolute map bound under IP-rotation floods
    private static final long THROTTLE_STALE_MS = 2 * AUDIT_THROTTLE_MS;
    private static final long PRUNE_INTERVAL_MS = 60_000;       // full-scan prune at most once a minute

    @Reference
    private SettingsService settingsService;

    @Reference
    private TorExitNodeFetcher torFetcher;

    @Reference
    private AuditLogger auditLogger;

    private final CidrListCache whitelistCache = new CidrListCache();
    private final CidrListCache blocklistCache = new CidrListCache();
    private final ConcurrentHashMap<String, Long> lastAuditPerIp = new ConcurrentHashMap<>();
    private final java.util.concurrent.atomic.AtomicLong lastPruneMs = new java.util.concurrent.atomic.AtomicLong(0L);
    private final LongSupplier clock;

    public BlocklistService() {
        this.clock = System::currentTimeMillis;
    }

    /** Test constructor with injectable collaborators and clock. */
    BlocklistService(SettingsService settingsService, TorExitNodeFetcher torFetcher,
                     AuditLogger auditLogger, LongSupplier clock) {
        this.settingsService = settingsService;
        this.torFetcher = torFetcher;
        this.auditLogger = auditLogger;
        this.clock = clock;
    }

    /**
     * Returns the block reason ({@link #REASON_STATIC} or {@link #REASON_TOR}) when the IP must
     * be rejected, or {@code null} when the request may proceed.
     */
    public String getBlockReason(String ip) {
        if (StringUtils.isBlank(ip) || settingsService == null) {
            return null;
        }
        GlobalSettings settings = settingsService.getGlobalSettings();
        if (!settings.isActivated()) {
            return null;
        }
        // Whitelist always wins: operators must always be able to exempt themselves.
        if (whitelistCache.matchesAny(ip, settings.getWhitelistIps())) {
            return null;
        }
        if (blocklistCache.matchesAny(ip, settings.getBlocklistIps())) {
            return REASON_STATIC;
        }
        if (settings.isTorBlocklistEnabled() && torFetcher != null && torFetcher.isTorExit(ip)) {
            return REASON_TOR;
        }
        return null;
    }

    /**
     * Records a blocked attempt: one INFO log line and one {@code BLOCKED} audit entry per IP per
     * {@link #AUDIT_THROTTLE_MS} (every hit is still visible at DEBUG). Both channels share the
     * throttle: a scanner hammering a blocked address must not be able to flood the application
     * log any more than the JCR audit trail. Never throws — rejecting the request matters more
     * than recording it.
     */
    public void onBlocked(String ip, String reason) {
        String sanitizedIp = AuditLogger.sanitize(ip);
        try {
            long now = clock.getAsLong();
            if (shouldAudit(ip, now)) {
                LOGGER.info("BFLP: Blocked auth attempt from blocklisted IP {} ({}); further hits from this IP are logged at DEBUG for the next hour",
                        sanitizedIp, reason);
                auditLogger.log(AuditLogger.EVENT_BLOCKED, ip, null, reason,
                        "blocked auth attempt (" + reason + ")");
            } else if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("BFLP: Blocked auth attempt from blocklisted IP {} ({})", sanitizedIp, reason);
            }
        } catch (RuntimeException e) {
            LOGGER.warn("BFLP: failed to audit blocked attempt from {}: {}", sanitizedIp, e.getMessage());
        }
    }

    /** Number of valid entries in the static blocklist (for status reporting). */
    public int getStaticEntryCount() {
        if (settingsService == null) {
            return 0;
        }
        return blocklistCache.validEntryCount(settingsService.getGlobalSettings().getBlocklistIps());
    }

    private boolean shouldAudit(String ip, long now) {
        pruneThrottleMapIfNeeded(now);
        Long prev = lastAuditPerIp.get(ip);
        if (prev != null) {
            if (now - prev < AUDIT_THROTTLE_MS) {
                return false;
            }
            // CAS so exactly one concurrent hit wins the new window.
            return lastAuditPerIp.replace(ip, prev, now);
        }
        // Hard memory bound: under a flood of distinct source IPs the map must not grow without
        // limit. Past the cap, new IPs are simply not audited (still visible at DEBUG) — dropping
        // an audit entry is preferable to letting attacker-controlled cardinality grow the heap.
        // Size check is approximate under concurrency, which is fine for a bound.
        if (lastAuditPerIp.size() >= THROTTLE_HARD_CAP) {
            return false;
        }
        return lastAuditPerIp.putIfAbsent(ip, now) == null;
    }

    /**
     * Bounds the throttle map's stale entries without an O(n) scan per request: the full-map
     * prune runs at most once per {@link #PRUNE_INTERVAL_MS} (CAS-elected thread) and only once
     * the map is past {@link #THROTTLE_PRUNE_THRESHOLD}. Entries older than twice the throttle
     * window are dropped (they can no longer suppress anything). The hot path therefore pays
     * amortized O(1); the absolute growth bound is {@link #THROTTLE_HARD_CAP} in shouldAudit.
     */
    private void pruneThrottleMapIfNeeded(long now) {
        if (lastAuditPerIp.size() <= THROTTLE_PRUNE_THRESHOLD) {
            return;
        }
        long last = lastPruneMs.get();
        if (now - last < PRUNE_INTERVAL_MS || !lastPruneMs.compareAndSet(last, now)) {
            return;
        }
        for (Map.Entry<String, Long> e : lastAuditPerIp.entrySet()) {
            if (now - e.getValue() >= THROTTLE_STALE_MS) {
                lastAuditPerIp.remove(e.getKey(), e.getValue());
            }
        }
    }

    int throttleMapSize() {
        return lastAuditPerIp.size();
    }
}
