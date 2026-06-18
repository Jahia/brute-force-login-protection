package org.jahia.modules.bruteforceloginprotection.core;

import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.core.IMap;
import org.jahia.modules.bruteforceloginprotection.hazelcast.HazelcastInstanceManager;
import org.jahia.modules.bruteforceloginprotection.spi.BanAction;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import static org.jahia.modules.bruteforceloginprotection.BruteForceLoginProtectionConstants.MAP_BANS;

@Component(immediate = true, service = UnbanScheduler.class)
public class UnbanScheduler {

    private static final Logger LOGGER = LoggerFactory.getLogger(UnbanScheduler.class);

    @Reference
    private HazelcastInstanceManager hazelcastManager;

    @Reference
    private BruteForceTracker tracker;

    @Reference
    private AuditLogger auditLogger;

    private ScheduledExecutorService executor;

    @Activate
    public void start() {
        executor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "bflp-unban-scheduler");
            t.setDaemon(true);
            return t;
        });
        executor.scheduleWithFixedDelay(this::sweep, 30, 30, TimeUnit.SECONDS);
    }

    @Deactivate
    public void stop() {
        if (executor != null) {
            executor.shutdownNow();
        }
    }

    public void sweep() {
        // scheduleWithFixedDelay permanently cancels the task if its run throws ANY Throwable, so
        // this method must never let one escape — a single uncaught error (even from a third-party
        // BanAction) would silently kill the unban sweep for the JVM's lifetime. Catch Throwable
        // around the ENTIRE body, including the audit-log trim, so a failure only skips one interval.
        try {
            HazelcastInstance hz = hazelcastManager.getHazelcastInstance();
            if (hz != null && hazelcastManager.isRunning()) {
                IMap<String, BannedIp> bans = hz.getMap(MAP_BANS);
                long now = System.currentTimeMillis();
                List<BannedIp> expired = new ArrayList<>();
                // Iterate a snapshot so a concurrent unbanIp()/eviction cannot make us skip an entry
                // mid-iteration. Only dispatch the unban actions for an entry that THIS sweep
                // actually removed (bans.remove(key) != null): a concurrent manual unbanIp() or
                // Hazelcast TTL eviction may have already removed it and dispatched onUnban, so
                // guarding on the remove result prevents a duplicate dispatch.
                for (Map.Entry<String, BannedIp> e : new ArrayList<>(bans.entrySet())) {
                    BannedIp b = e.getValue();
                    // Value-checked remove: a concurrent re-ban could install a fresh (non-expired)
                    // BannedIp under the same key between our snapshot read and this remove. The
                    // value-less remove(key) would silently drop that fresh ban; remove(key, b)
                    // only deletes when the entry is STILL the expired one we observed.
                    if (b != null && b.isExpired(now) && bans.remove(e.getKey(), b)) {
                        expired.add(b);
                    }
                }
                for (BannedIp b : expired) {
                    tracker.removeBanFromJcr(b.getIp());
                    auditLogger.log(AuditLogger.EVENT_UNBAN, b.getIp(), b.getJailName(), b.getSourceName(), "auto-unban");
                    BanContext ctx = BanContext.builder()
                            .ip(b.getIp())
                            .jailName(b.getJailName())
                            .sourceName(b.getSourceName())
                            .bannedAt(b.getBannedAt())
                            .bannedUntil(b.getBannedUntil())
                            .banCount(b.getBanCount())
                            .reason(b.getReason())
                            .build();
                    dispatchUnbanActions(ctx);
                }
            }
            // Trim the audit log periodically instead of on every write (avoids an O(n) JCR scan
            // on the hot login-failure recording path).
            auditLogger.trimAuditLog();
        } catch (Throwable t) { // NOSONAR S1181: scheduleWithFixedDelay cancels the task on any escaping Throwable; we must swallow it so the recurring sweep survives.
            LOGGER.error("BFLP: unban sweep failed; will retry on next interval", t);
        }
    }

    private void dispatchUnbanActions(BanContext ctx) {
        for (BanAction action : tracker.getBanActions()) {
            try {
                action.onUnban(ctx);
            } catch (Exception ex) {
                LOGGER.debug("BFLP: BanAction {} failed onUnban: {}", action.getName(), ex.getMessage());
            }
        }
    }
}
