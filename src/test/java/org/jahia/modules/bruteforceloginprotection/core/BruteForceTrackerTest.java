package org.jahia.modules.bruteforceloginprotection.core;

import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.core.IMap;
import org.jahia.modules.bruteforceloginprotection.hazelcast.HazelcastInstanceManager;
import org.jahia.modules.bruteforceloginprotection.spi.BanAction;
import org.jahia.modules.bruteforceloginprotection.spi.FailureEvent;
import org.jahia.services.content.JCRCallback;
import org.jahia.services.content.JCRTemplate;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import java.lang.reflect.Field;
import java.util.Collections;
import java.util.HashMap;
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
        return FailureEvent.builder()
                .ip(ip)
                .sourceName("test-source")
                .jailName("login")
                .timestampMs(System.currentTimeMillis())
                .username("alice")
                .userAgent("agent")
                .requestPath("/cms/login")
                .extras(new HashMap<>())
                .build();
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
}
