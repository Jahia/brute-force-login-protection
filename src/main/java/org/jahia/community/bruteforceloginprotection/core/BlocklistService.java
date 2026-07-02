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
    static final int THROTTLE_PRUNE_THRESHOLD = 10_000;         // bound memory under IP-rotation floods
    private static final long THROTTLE_STALE_MS = 2 * AUDIT_THROTTLE_MS;

    @Reference
    private SettingsService settingsService;

    @Reference
    private TorExitNodeFetcher torFetcher;

    @Reference
    private AuditLogger auditLogger;

    private final CidrListCache whitelistCache = new CidrListCache();
    private final CidrListCache blocklistCache = new CidrListCache();
    private final ConcurrentHashMap<String, Long> lastAuditPerIp = new ConcurrentHashMap<>();
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
     * Records a blocked attempt: INFO log line on every hit, {@code BLOCKED} audit entry at most
     * once per IP per {@link #AUDIT_THROTTLE_MS}. Never throws — rejecting the request matters
     * more than recording it.
     */
    public void onBlocked(String ip, String reason) {
        String sanitizedIp = AuditLogger.sanitize(ip);
        if (LOGGER.isInfoEnabled()) {
            LOGGER.info("BFLP: Blocked auth attempt from blocklisted IP {} ({})", sanitizedIp, reason);
        }
        try {
            long now = clock.getAsLong();
            if (shouldAudit(ip, now)) {
                auditLogger.log(AuditLogger.EVENT_BLOCKED, ip, null, reason,
                        "blocked auth attempt (" + reason + ")");
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
        boolean[] audit = new boolean[1];
        lastAuditPerIp.compute(ip, (k, prev) -> {
            if (prev == null || now - prev >= AUDIT_THROTTLE_MS) {
                audit[0] = true;
                return now;
            }
            return prev;
        });
        return audit[0];
    }

    /**
     * Opportunistic bound on the throttle map: when an attacker rotates source IPs the map would
     * otherwise grow one entry per distinct IP. Past the threshold, entries older than twice the
     * throttle window are dropped (they can no longer suppress anything).
     */
    private void pruneThrottleMapIfNeeded(long now) {
        if (lastAuditPerIp.size() <= THROTTLE_PRUNE_THRESHOLD) {
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
