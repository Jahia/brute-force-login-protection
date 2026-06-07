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
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
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
        try {
            HazelcastInstance hz = hazelcastManager.getHazelcastInstance();
            if (hz == null || !hazelcastManager.isRunning()) {
                return;
            }
            IMap<String, BannedIp> bans = hz.getMap(MAP_BANS);
            long now = System.currentTimeMillis();
            Set<String> toRemove = new HashSet<>();
            List<BannedIp> expired = new ArrayList<>();
            for (Map.Entry<String, BannedIp> e : bans.entrySet()) {
                BannedIp b = e.getValue();
                if (b != null && b.isExpired(now)) {
                    toRemove.add(e.getKey());
                    expired.add(b);
                }
            }
            for (String key : toRemove) {
                bans.remove(key);
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
        } catch (Exception e) {
            LOGGER.warn("BFLP: unban sweep failed: {}", e.getMessage());
        }
        // Trim the audit log periodically instead of on every write (avoids an O(n) JCR scan
        // on the hot login-failure recording path).
        auditLogger.trimAuditLog();
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
