package org.jahia.community.bruteforceloginprotection.core;

import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.core.IMap;
import com.hazelcast.core.LifecycleService;
import org.jahia.community.bruteforceloginprotection.hazelcast.HazelcastInstanceManager;
import org.jahia.community.bruteforceloginprotection.spi.BanAction;
import org.jahia.community.bruteforceloginprotection.spi.FailureEvent;
import org.jahia.services.content.JCRCallback;
import org.jahia.services.content.JCRTemplate;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import javax.jcr.RepositoryException;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class BruteForceTrackerTest {

    private BruteForceTracker tracker;
    private SettingsService settingsService;
    private HazelcastInstanceManager hazelcastManager;
    private HazelcastInstance hazelcast;
    private AuditLogger auditLogger;
    private JCRTemplate jcrTemplate;
    private IMap<String, FailureWindow> windowsMap;
    private IMap<String, BannedIp> bansMap;
    private Map<String, FailureWindow> windowsStore;
    private Map<String, BannedIp> bansStore;

    @SuppressWarnings("unchecked")
    @Before
    public void setUp() throws Exception {
        tracker = new BruteForceTracker();
        settingsService = mock(SettingsService.class);
        hazelcastManager = mock(HazelcastInstanceManager.class);
        hazelcast = mock(HazelcastInstance.class);
        auditLogger = mock(AuditLogger.class);
        jcrTemplate = mock(JCRTemplate.class);
        windowsMap = mock(IMap.class);
        bansMap = mock(IMap.class);
        windowsStore = new ConcurrentHashMap<>();
        bansStore = new ConcurrentHashMap<>();

        when(hazelcastManager.getHazelcastInstance()).thenReturn(hazelcast);
        LifecycleService lifecycleService = mock(LifecycleService.class);
        when(hazelcast.getLifecycleService()).thenReturn(lifecycleService);
        when(lifecycleService.isRunning()).thenReturn(true);
        when(hazelcast.<String, FailureWindow>getMap("bflp:windows")).thenReturn(windowsMap);
        when(hazelcast.<String, BannedIp>getMap("bflp:bans")).thenReturn(bansMap);
        when(hazelcast.getMap("bflp:notifMarkers")).thenReturn(mock(IMap.class));

        // wire window/ban "storage" through the mocked IMap
        when(windowsMap.get(anyString())).thenAnswer(inv -> windowsStore.get((String) inv.getArgument(0)));
        when(windowsMap.remove(anyString())).thenAnswer(inv -> windowsStore.remove((String) inv.getArgument(0)));
        when(windowsMap.put(anyString(), any(FailureWindow.class), anyLong(), any(TimeUnit.class)))
                .thenAnswer(inv -> windowsStore.put(inv.getArgument(0), inv.getArgument(1)));
        when(windowsMap.put(anyString(), any(FailureWindow.class)))
                .thenAnswer(inv -> windowsStore.put(inv.getArgument(0), inv.getArgument(1)));

        when(bansMap.get(anyString())).thenAnswer(inv -> bansStore.get((String) inv.getArgument(0)));
        when(bansMap.remove(anyString())).thenAnswer(inv -> bansStore.remove((String) inv.getArgument(0)));
        // Value-checked overload used by isIpCurrentlyBanned's expired-entry backstop to avoid
        // evicting a concurrently re-installed fresh ban.
        when(bansMap.remove(anyString(), any())).thenAnswer(inv ->
                bansStore.remove(inv.getArgument(0), inv.getArgument(1)));
        when(bansMap.put(anyString(), any(BannedIp.class), anyLong(), any(TimeUnit.class)))
                .thenAnswer(inv -> bansStore.put(inv.getArgument(0), inv.getArgument(1)));
        when(bansMap.putIfAbsent(anyString(), any(BannedIp.class), anyLong(), any(TimeUnit.class)))
                .thenAnswer(inv -> {
                    String k = inv.getArgument(0);
                    BannedIp v = inv.getArgument(1);
                    return bansStore.putIfAbsent(k, v);
                });
        when(bansMap.replace(anyString(), any(BannedIp.class), any(BannedIp.class)))
                .thenAnswer(inv -> {
                    String k = inv.getArgument(0);
                    BannedIp oldV = inv.getArgument(1);
                    BannedIp newV = inv.getArgument(2);
                    BannedIp cur = bansStore.get(k);
                    if (cur == oldV || (cur != null && cur.equals(oldV))) {
                        bansStore.put(k, newV);
                        return true;
                    }
                    return false;
                });

        // JCR template: just execute the callback against a no-op-ish path or short-circuit
        // For mirrorBanToJcr & readBanCountFromJcr, return 0 / no-op by NOT executing the callback.
        when(jcrTemplate.doExecuteWithSystemSessionAsUser(any(), anyString(), any(), any(JCRCallback.class)))
                .thenReturn(0);

        inject(tracker, "hazelcastManager", hazelcastManager);
        inject(tracker, "settingsService", settingsService);
        inject(tracker, "auditLogger", auditLogger);
        inject(tracker, "jcrTemplate", jcrTemplate);
    }

    private static void inject(Object target, String fieldName, Object value) throws Exception {
        Field f = target.getClass().getDeclaredField(fieldName);
        f.setAccessible(true);
        f.set(target, value);
    }

    private GlobalSettings activeSettings() {
        return GlobalSettings.builder()
                .activated(true)
                .whitelistIps("127.0.0.1/32,::1/128")
                .ignorePatterns(Collections.emptyList())
                .auditLogMaxEntries(1000)
                .recidiveFactor(2.0)
                .maxBanTimeSec(86400L)
                .build();
    }

    private GlobalSettings inactiveSettings() {
        return GlobalSettings.builder()
                .activated(false)
                .whitelistIps("")
                .ignorePatterns(Collections.emptyList())
                .auditLogMaxEntries(1000)
                .recidiveFactor(2.0)
                .maxBanTimeSec(86400L)
                .build();
    }

    private JailConfig loginJail(int maxRetry, long findTimeSec, long banTimeSec) {
        return new JailConfig("login", true, maxRetry, findTimeSec, banTimeSec);
    }

    private FailureEvent failureFor(String ip) {
        return failureFor(ip, "alice");
    }

    private FailureEvent failureFor(String ip, String username) {
        return FailureEvent.builder()
                .ip(ip)
                .sourceName("test-source")
                .jailName("login")
                .timestampMs(System.currentTimeMillis())
                .username(username)
                .userAgent("agent")
                .requestPath("/cms/login")
                .extras(new HashMap<>())
                .build();
    }

    @Test
    public void banManuallyRejectsNonIpValue() {
        // S1: a hostname or garbage value must never be stored as a ban (no DNS lookup, no poisoning).
        assertThat(tracker.banManually("evil.example.com", "login", 300, "reason")).isFalse();
        assertThat(tracker.banManually("not-an-ip", null, null, null)).isFalse();
        assertThat(bansStore).isEmpty();
        verify(auditLogger, never()).log(eq(AuditLogger.EVENT_BAN), anyString(), anyString(), anyString(), anyString());
    }

    @Test
    public void banManuallyWithValidIpCreatesBan() {
        when(settingsService.getGlobalSettings()).thenReturn(activeSettings());
        when(settingsService.getJail("login")).thenReturn(loginJail(3, 60L, 60L));

        assertThat(tracker.banManually("203.0.113.7", "login", 300, "manual test")).isTrue();

        assertThat(bansStore).containsKey("203.0.113.7");
        assertThat(bansStore.get("203.0.113.7").getBannedUntil()).isGreaterThan(System.currentTimeMillis());
    }

    @Test
    public void isIpCurrentlyBannedFailsOpenWhenHazelcastNotRunning() {
        // R4: if the distributed store is down we fail open (do not block logins) even with a ban present.
        when(hazelcast.getLifecycleService().isRunning()).thenReturn(false);
        long now = System.currentTimeMillis();
        bansStore.put("4.4.4.4", new BannedIp("4.4.4.4", "login", "manual", now, now + 60000L, 1, "x"));
        assertThat(tracker.isIpCurrentlyBanned("4.4.4.4")).isFalse();
    }

    @Test
    public void deactivatedSettingsSkipRecord() {
        when(settingsService.getGlobalSettings()).thenReturn(inactiveSettings());
        tracker.recordEvent(failureFor("10.0.0.1"));
        verify(auditLogger, never()).log(anyString(), anyString(), anyString(), anyString(), anyString());
        assertThat(windowsStore).isEmpty();
        assertThat(bansStore).isEmpty();
    }

    @Test
    public void whitelistedIpNotTracked() {
        when(settingsService.getGlobalSettings()).thenReturn(activeSettings());
        when(settingsService.getJail("login")).thenReturn(loginJail(3, 60L, 60L));
        tracker.recordEvent(failureFor("127.0.0.1"));
        verify(auditLogger, never()).log(anyString(), anyString(), anyString(), anyString(), anyString());
        assertThat(windowsStore).isEmpty();
        assertThat(bansStore).isEmpty();
    }

    @Test
    public void nullIpEventIgnored() {
        when(settingsService.getGlobalSettings()).thenReturn(activeSettings());
        FailureEvent ev = FailureEvent.builder()
                .sourceName("src").jailName("login").timestampMs(0L)
                .username("u").userAgent("a").requestPath("/p")
                .build();
        tracker.recordEvent(ev);
        tracker.recordEvent(null);
        verify(auditLogger, never()).log(anyString(), anyString(), anyString(), anyString(), anyString());
    }

    @Test
    public void failureBelowThresholdIncrementsWindow() {
        when(settingsService.getGlobalSettings()).thenReturn(activeSettings());
        when(settingsService.getJail("login")).thenReturn(loginJail(3, 60L, 60L));

        tracker.recordEvent(failureFor("10.0.0.5"));

        assertThat(windowsStore).hasSize(1);
        FailureWindow w = windowsStore.get("10.0.0.5|login");
        assertThat(w).isNotNull();
        assertThat(w.size()).isEqualTo(1);
        assertThat(bansStore).isEmpty();
        verify(auditLogger, atLeastOnce()).log(eq(AuditLogger.EVENT_FAILURE), eq("10.0.0.5"),
                eq("login"), anyString(), anyString());
        verify(auditLogger, never()).log(eq(AuditLogger.EVENT_BAN), anyString(), anyString(),
                anyString(), anyString());
    }

    @Test
    public void crossingThresholdIssuesBanAndDispatchesActions() {
        when(settingsService.getGlobalSettings()).thenReturn(activeSettings());
        when(settingsService.getJail("login")).thenReturn(loginJail(2, 60L, 60L));

        BanAction action = mock(BanAction.class);
        when(action.priority()).thenReturn(1);
        when(action.getName()).thenReturn("test-action");
        tracker.addBanAction(action);

        tracker.recordEvent(failureFor("10.0.0.6"));
        tracker.recordEvent(failureFor("10.0.0.6"));

        assertThat(bansStore).containsKey("10.0.0.6");
        BannedIp banned = bansStore.get("10.0.0.6");
        assertThat(banned.getJailName()).isEqualTo("login");
        assertThat(banned.getBanCount()).isEqualTo(1);

        // window should have been removed after ban
        assertThat(windowsStore).doesNotContainKey("10.0.0.6|login");

        verify(auditLogger).log(eq(AuditLogger.EVENT_BAN), eq("10.0.0.6"), eq("login"),
                anyString(), anyString());
        verify(action, times(1)).onBan(any(BanContext.class));
    }

    @Test
    public void isIpCurrentlyBannedReturnsTrueForActiveBan() {
        when(settingsService.getGlobalSettings()).thenReturn(activeSettings());
        long now = System.currentTimeMillis();
        BannedIp banned = new BannedIp("10.0.0.7", "login", "src",
                now, now + 60_000L, 1, "reason");
        bansStore.put("10.0.0.7", banned);

        assertThat(tracker.isIpCurrentlyBanned("10.0.0.7")).isTrue();
    }

    @Test
    public void isIpCurrentlyBannedRemovesExpiredEntry() {
        long now = System.currentTimeMillis();
        BannedIp expired = new BannedIp("10.0.0.8", "login", "src",
                now - 120_000L, now - 60_000L, 1, "reason");
        bansStore.put("10.0.0.8", expired);

        assertThat(tracker.isIpCurrentlyBanned("10.0.0.8")).isFalse();
        assertThat(bansStore).doesNotContainKey("10.0.0.8");
    }

    @Test
    public void isIpCurrentlyBannedReturnsFalseForUnknownOrBlank() {
        assertThat(tracker.isIpCurrentlyBanned("10.0.0.9")).isFalse();
        assertThat(tracker.isIpCurrentlyBanned("")).isFalse();
        assertThat(tracker.isIpCurrentlyBanned(null)).isFalse();
    }

    @Test
    public void recidiveSecondBanIncrementsBanCount() {
        when(settingsService.getGlobalSettings()).thenReturn(activeSettings());
        when(settingsService.getJail("login")).thenReturn(loginJail(1, 60L, 60L));

        // First ban
        tracker.recordEvent(failureFor("10.0.0.10"));
        BannedIp first = bansStore.get("10.0.0.10");
        assertThat(first).isNotNull();
        assertThat(first.getBanCount()).isEqualTo(1);

        // Second event for same IP - existing ban present in map, banCount += 1
        tracker.recordEvent(failureFor("10.0.0.10"));
        BannedIp second = bansStore.get("10.0.0.10");
        assertThat(second.getBanCount()).isEqualTo(2);
    }

    @Test
    public void manualBanThenUnbanRoundTrip() {
        when(settingsService.getGlobalSettings()).thenReturn(activeSettings());
        when(settingsService.getJail(anyString())).thenReturn(loginJail(3, 60L, 60L));

        BanAction action = mock(BanAction.class);
        when(action.priority()).thenReturn(1);
        when(action.getName()).thenReturn("test-action");
        tracker.addBanAction(action);

        assertThat(tracker.banManually("10.0.0.99", "login", 30, "cypress")).isTrue();
        assertThat(bansStore).containsKey("10.0.0.99");

        ArgumentCaptor<BanContext> ctx = ArgumentCaptor.forClass(BanContext.class);
        verify(action).onBan(ctx.capture());
        assertThat(ctx.getValue().getIp()).isEqualTo("10.0.0.99");

        assertThat(tracker.unbanIp("10.0.0.99")).isTrue();
        assertThat(bansStore).doesNotContainKey("10.0.0.99");
        verify(action).onUnban(any(BanContext.class));
    }

    @Test
    public void banActionsAreReturnedSortedByPriority() {
        BanAction high = mock(BanAction.class);
        when(high.priority()).thenReturn(10);
        when(high.getName()).thenReturn("high");
        BanAction low = mock(BanAction.class);
        when(low.priority()).thenReturn(1);
        when(low.getName()).thenReturn("low");
        tracker.addBanAction(high);
        tracker.addBanAction(low);

        assertThat(tracker.getBanActions().get(0).getName()).isEqualTo("low");
        assertThat(tracker.getBanActions().get(1).getName()).isEqualTo("high");

        tracker.removeBanAction(low);
        assertThat(tracker.getBanActions()).hasSize(1);
    }

    // -------------------------------------------------------------------------------------------
    // F6-a (downgraded, full rewrite) — 3 out-of-order BanActions, real threshold-crossing ban,
    // assert BOTH sort order AND all three onBan() invocations together (the previously-existing
    // tests each asserted only one half of this compound claim).
    // -------------------------------------------------------------------------------------------

    @Test
    public void threeOutOfOrderBanActionsAreAllDispatchedAndSortedOnRealBan() {
        when(settingsService.getGlobalSettings()).thenReturn(activeSettings());
        when(settingsService.getJail("login")).thenReturn(loginJail(1, 60L, 60L));

        BanAction actionPriority20 = mock(BanAction.class);
        when(actionPriority20.priority()).thenReturn(20);
        when(actionPriority20.getName()).thenReturn("p20");
        BanAction actionPriority0 = mock(BanAction.class);
        when(actionPriority0.priority()).thenReturn(0);
        when(actionPriority0.getName()).thenReturn("p0");
        BanAction actionPriority10 = mock(BanAction.class);
        when(actionPriority10.priority()).thenReturn(10);
        when(actionPriority10.getName()).thenReturn("p10");

        // Registered out of priority order on purpose.
        tracker.addBanAction(actionPriority20);
        tracker.addBanAction(actionPriority0);
        tracker.addBanAction(actionPriority10);

        // Single event crosses maxRetry=1, triggering a real ban via recordEvent -> doBan.
        tracker.recordEvent(failureFor("10.0.0.50"));

        assertThat(bansStore).containsKey("10.0.0.50");

        List<BanAction> sorted = tracker.getBanActions();
        assertThat(sorted).extracting(BanAction::getName).containsExactly("p0", "p10", "p20");

        verify(actionPriority20, times(1)).onBan(any(BanContext.class));
        verify(actionPriority0, times(1)).onBan(any(BanContext.class));
        verify(actionPriority10, times(1)).onBan(any(BanContext.class));
    }

    // -------------------------------------------------------------------------------------------
    // F26 — Known limitation: IP-keyed counting only. Two different usernames from the same IP
    // land in the SAME sliding-window entry and jointly count toward the same threshold.
    // -------------------------------------------------------------------------------------------

    @Test
    public void differentUsernamesFromSameIpShareTheSameFailureWindow() {
        when(settingsService.getGlobalSettings()).thenReturn(activeSettings());
        when(settingsService.getJail("login")).thenReturn(loginJail(2, 60L, 60L));

        tracker.recordEvent(failureFor("10.0.0.60", "alice"));
        tracker.recordEvent(failureFor("10.0.0.60", "bob"));

        // Both events (different usernames, same IP) jointly crossed maxRetry=2 -> banned.
        assertThat(bansStore).containsKey("10.0.0.60");
        assertThat(windowsStore).doesNotContainKey("10.0.0.60|login");
    }

    // -------------------------------------------------------------------------------------------
    // F27 — Known limitation: dual source of truth. A JCR mirror-write failure must not roll
    // back (or prevent) the Hazelcast ban — the module intentionally favors availability of the
    // enforcement path over mirror consistency.
    // -------------------------------------------------------------------------------------------

    @Test
    public void jcrMirrorWriteFailureDoesNotRollBackHazelcastBan() throws Exception {
        when(settingsService.getGlobalSettings()).thenReturn(activeSettings());
        when(settingsService.getJail(anyString())).thenReturn(loginJail(3, 60L, 60L));

        // First invocation = readBanCountFromJcr (succeeds, returns 0); second invocation =
        // mirrorBanToJcr's callback (simulated JCR mirror-write failure).
        when(jcrTemplate.doExecuteWithSystemSessionAsUser(any(), anyString(), any(), any(JCRCallback.class)))
                .thenReturn(0)
                .thenThrow(new RepositoryException("simulated JCR mirror write failure"));

        boolean result = tracker.banManually("10.0.0.70", "login", 120, "jcr-failure-test");

        assertThat(result).isTrue();
        assertThat(bansStore).containsKey("10.0.0.70");
        assertThat(tracker.isIpCurrentlyBanned("10.0.0.70")).isTrue();
    }

    // -------------------------------------------------------------------------------------------
    // F17-a residual — manual-ban duration is clamped to maxBanTimeSeconds.
    // -------------------------------------------------------------------------------------------

    @Test
    public void banManuallyClampsDurationToMaxBanTimeSeconds() {
        GlobalSettings clampedSettings = GlobalSettings.builder()
                .activated(true)
                .whitelistIps("")
                .ignorePatterns(Collections.emptyList())
                .auditLogMaxEntries(1000)
                .recidiveFactor(2.0)
                .maxBanTimeSec(100L)
                .build();
        when(settingsService.getGlobalSettings()).thenReturn(clampedSettings);
        when(settingsService.getJail("login")).thenReturn(loginJail(3, 60L, 60L));

        long before = System.currentTimeMillis();
        assertThat(tracker.banManually("10.0.0.80", "login", 100_000, "too long")).isTrue();

        BannedIp banned = bansStore.get("10.0.0.80");
        assertThat(banned).isNotNull();
        // Clamped to maxBanTimeSec=100s, NOT the requested 100_000s.
        assertThat(banned.getBannedUntil()).isLessThanOrEqualTo(before + 101_000L);
        assertThat(banned.getBannedUntil()).isGreaterThan(before + 99_000L);
    }

    // -------------------------------------------------------------------------------------------
    // F11 residual — getHazelcastInstance() itself returning null (distinct from "not running").
    // -------------------------------------------------------------------------------------------

    @Test
    public void isIpCurrentlyBannedFailsOpenWhenHazelcastInstanceIsNull() {
        when(hazelcastManager.getHazelcastInstance()).thenReturn(null);
        assertThat(tracker.isIpCurrentlyBanned("6.6.6.6")).isFalse();
    }

    // -------------------------------------------------------------------------------------------
    // A genuine (not mocked) ReDoS-timeout race is still intentionally NOT tested here, because a
    // real backtrack takes seconds to minutes of wall clock and would make the suite slow.
    //
    // An earlier note here recorded that "^(a+)+$" resolved well within the 50ms budget even at 40
    // characters, and read that as "a real timeout is hard to trigger". The correct reading is that
    // Java's regex optimiser makes the TEXTBOOK nested-quantifier forms harmless -- measured 0ms for
    // ^(a+)+$, (a*)*$, (a|a)+$ and (x+x+)+y -- while a bounded repetition over a group containing an
    // unbounded quantifier is not: (.*a){20} takes ~8s at 28 characters and ~101s at 32.
    // That inversion is why RegexSafetyCheck used to reject the harmless shapes and admit the
    // dangerous one, and it is why the lint is documented as best-effort rather than as the control.
    //
    // The disposition itself -- an unevaluated pattern must not grant an exemption -- is covered
    // deterministically by BruteForceTrackerIgnorePatternTest (timeout, saturation and shutdown),
    // which is the property that actually matters (GHSA-7qgr-2hqv-r344).
    // -------------------------------------------------------------------------------------------
}
