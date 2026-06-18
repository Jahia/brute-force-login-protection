package org.jahia.modules.bruteforceloginprotection.core;

import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.core.IMap;
import org.jahia.modules.bruteforceloginprotection.hazelcast.HazelcastInstanceManager;
import org.jahia.modules.bruteforceloginprotection.spi.BanAction;
import org.junit.Before;
import org.junit.Test;

import java.lang.reflect.Field;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link UnbanScheduler#sweep()}.
 *
 * The executor lifecycle (@Activate / @Deactivate) is not exercised here because it requires
 * the OSGi container. Only the sweep() logic is tested directly.
 */
public class UnbanSchedulerTest {

    private UnbanScheduler scheduler;
    private HazelcastInstanceManager hazelcastManager;
    private HazelcastInstance hazelcast;
    private BruteForceTracker tracker;
    private AuditLogger auditLogger;

    // In-memory store backing the mocked IMap
    private Map<String, BannedIp> bansStore;

    @SuppressWarnings("unchecked")
    private IMap<String, BannedIp> bansMap;

    @Before
    @SuppressWarnings("unchecked")
    public void setUp() throws Exception {
        scheduler = new UnbanScheduler();
        hazelcastManager = mock(HazelcastInstanceManager.class);
        hazelcast = mock(HazelcastInstance.class);
        tracker = mock(BruteForceTracker.class);
        auditLogger = mock(AuditLogger.class);
        bansMap = mock(IMap.class);
        bansStore = new ConcurrentHashMap<>();

        when(hazelcastManager.getHazelcastInstance()).thenReturn(hazelcast);
        when(hazelcastManager.isRunning()).thenReturn(true);
        when(hazelcast.<String, BannedIp>getMap("bflp:bans")).thenReturn(bansMap);

        // Wire bansMap to bansStore so entrySet, remove behave realistically
        when(bansMap.entrySet()).thenAnswer(inv -> new java.util.HashSet<>(bansStore.entrySet()));
        when(bansMap.remove(anyString())).thenAnswer(inv -> bansStore.remove((String) inv.getArgument(0)));
        // Value-checked overload used by sweep() to avoid dropping a concurrently re-installed ban
        when(bansMap.remove(anyString(), any())).thenAnswer(inv ->
                bansStore.remove(inv.getArgument(0), inv.getArgument(1)));

        inject(scheduler, "hazelcastManager", hazelcastManager);
        inject(scheduler, "tracker", tracker);
        inject(scheduler, "auditLogger", auditLogger);
    }

    private static void inject(Object target, String fieldName, Object value) throws Exception {
        Field f = target.getClass().getDeclaredField(fieldName);
        f.setAccessible(true);
        f.set(target, value);
    }

    private BannedIp expiredBan(String ip) {
        long now = System.currentTimeMillis();
        return new BannedIp(ip, "login", "form", now - 120_000L, now - 60_000L, 1, "expired");
    }

    private BannedIp activeBan(String ip) {
        long now = System.currentTimeMillis();
        return new BannedIp(ip, "login", "form", now - 10_000L, now + 60_000L, 1, "active");
    }

    // -------------------------------------------------------------------------
    // 1. Expired bans are removed and onUnban is dispatched
    // -------------------------------------------------------------------------

    @Test
    public void sweep_expiredBan_removedAndOnUnbanDispatched() {
        BanAction action = mock(BanAction.class);
        when(action.getName()).thenReturn("test");
        when(tracker.getBanActions()).thenReturn(List.of(action));

        BannedIp expired = expiredBan("10.0.0.1");
        bansStore.put("10.0.0.1", expired);

        scheduler.sweep();

        // Entry must be gone from the store
        assertThat(bansStore).doesNotContainKey("10.0.0.1");
        // JCR mirror must be cleaned
        verify(tracker).removeBanFromJcr("10.0.0.1");
        // Audit log must record the auto-unban
        verify(auditLogger).log(eq(AuditLogger.EVENT_UNBAN), eq("10.0.0.1"),
                anyString(), anyString(), anyString());
        // onUnban action must be called exactly once
        verify(action, times(1)).onUnban(any(BanContext.class));
        // Audit log trim must always run
        verify(auditLogger).trimAuditLog();
    }

    // -------------------------------------------------------------------------
    // 2. Non-expired bans are left in the store
    // -------------------------------------------------------------------------

    @Test
    public void sweep_activeBan_notRemovedAndOnUnbanNotDispatched() {
        when(tracker.getBanActions()).thenReturn(List.of());

        BannedIp active = activeBan("10.0.0.2");
        bansStore.put("10.0.0.2", active);

        scheduler.sweep();

        // bansMap.remove was attempted but bansStore still contains the key
        // because mock remove only removes when called; we want to verify remove
        // was NOT called for this key (the sweep should not attempt to remove a live ban).
        verify(bansMap, never()).remove("10.0.0.2");
        verify(tracker, never()).removeBanFromJcr("10.0.0.2");
        verify(auditLogger, never()).log(eq(AuditLogger.EVENT_UNBAN),
                anyString(), anyString(), anyString(), anyString());
        verify(auditLogger).trimAuditLog();
    }

    // -------------------------------------------------------------------------
    // 3. Mixed: one expired, one active
    // -------------------------------------------------------------------------

    @Test
    public void sweep_mixedBans_onlyExpiredRemoved() {
        BanAction action = mock(BanAction.class);
        when(action.getName()).thenReturn("test");
        when(tracker.getBanActions()).thenReturn(List.of(action));

        bansStore.put("10.0.0.3", expiredBan("10.0.0.3"));
        bansStore.put("10.0.0.4", activeBan("10.0.0.4"));

        scheduler.sweep();

        verify(tracker).removeBanFromJcr("10.0.0.3");
        verify(tracker, never()).removeBanFromJcr("10.0.0.4");
        verify(action, times(1)).onUnban(any(BanContext.class));
    }

    // -------------------------------------------------------------------------
    // 4. Exception thrown inside sweep() must NOT propagate
    //    (scheduleWithFixedDelay would cancel the task permanently if it did)
    // -------------------------------------------------------------------------

    @Test
    public void sweep_exceptionInBody_doesNotPropagate() {
        when(tracker.getBanActions()).thenThrow(new RuntimeException("simulated failure"));

        BannedIp expired = expiredBan("10.0.0.5");
        bansStore.put("10.0.0.5", expired);

        // Must complete without throwing
        assertThatCode(() -> scheduler.sweep()).doesNotThrowAnyException();
    }

    // -------------------------------------------------------------------------
    // 5. Duplicate-dispatch guard: if bans.remove() returns null (concurrent removal)
    //    onUnban must NOT be called for that entry
    // -------------------------------------------------------------------------

    @Test
    @SuppressWarnings("unchecked")
    public void sweep_concurrentRemoval_doesNotDoubleDispatch() {
        BanAction action = mock(BanAction.class);
        when(action.getName()).thenReturn("test");
        when(tracker.getBanActions()).thenReturn(List.of(action));

        BannedIp expired = expiredBan("10.0.0.6");
        bansStore.put("10.0.0.6", expired);

        // Simulate a concurrent manual unban that already removed the entry:
        // bansMap.remove() returns null (already gone), so sweep must skip dispatch.
        IMap<String, BannedIp> concurrentMap = mock(IMap.class);
        when(concurrentMap.entrySet()).thenReturn(
                new java.util.HashSet<>(Map.of("10.0.0.6", expired).entrySet()));
        when(concurrentMap.remove("10.0.0.6")).thenReturn(null); // already removed concurrently
        when(hazelcast.<String, BannedIp>getMap("bflp:bans")).thenReturn(concurrentMap);

        scheduler.sweep();

        // onUnban must NOT fire because remove() returned null
        verify(action, never()).onUnban(any(BanContext.class));
        verify(tracker, never()).removeBanFromJcr("10.0.0.6");
        verify(auditLogger).trimAuditLog();
    }

    // -------------------------------------------------------------------------
    // 6. Hazelcast not running: sweep does nothing, no exception
    // -------------------------------------------------------------------------

    @Test
    public void sweep_hazelcastNotRunning_skipsWithNoException() {
        when(hazelcastManager.isRunning()).thenReturn(false);

        assertThatCode(() -> scheduler.sweep()).doesNotThrowAnyException();

        verify(tracker, never()).removeBanFromJcr(anyString());
        verify(auditLogger).trimAuditLog();
    }

    // -------------------------------------------------------------------------
    // 7. Hazelcast null: sweep does nothing, no exception
    // -------------------------------------------------------------------------

    @Test
    public void sweep_hazelcastNull_skipsWithNoException() {
        when(hazelcastManager.getHazelcastInstance()).thenReturn(null);

        assertThatCode(() -> scheduler.sweep()).doesNotThrowAnyException();

        verify(tracker, never()).removeBanFromJcr(anyString());
        verify(auditLogger).trimAuditLog();
    }

    // -------------------------------------------------------------------------
    // 8. Empty ban map: sweep completes cleanly
    // -------------------------------------------------------------------------

    @Test
    public void sweep_emptyBanMap_completesWithNoActions() {
        when(tracker.getBanActions()).thenReturn(List.of());

        assertThatCode(() -> scheduler.sweep()).doesNotThrowAnyException();

        verify(tracker, never()).removeBanFromJcr(anyString());
        verify(auditLogger).trimAuditLog();
    }
}
