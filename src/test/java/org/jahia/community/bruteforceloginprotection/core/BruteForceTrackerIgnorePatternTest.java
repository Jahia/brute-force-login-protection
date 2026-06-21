package org.jahia.community.bruteforceloginprotection.core;

import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.core.IMap;
import com.hazelcast.core.LifecycleService;
import org.jahia.community.bruteforceloginprotection.hazelcast.HazelcastInstanceManager;
import org.jahia.community.bruteforceloginprotection.spi.FailureEvent;
import org.jahia.services.content.JCRCallback;
import org.jahia.services.content.JCRTemplate;
import org.junit.Before;
import org.junit.Test;

import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for the ignore-pattern matching path in {@link BruteForceTracker#recordEvent}.
 *
 * The tracker is wired with a real ignorePatternExecutor by calling activate() after injection,
 * so the actual regex-matching (including the timeout / fail-closed path) is exercised.
 */
public class BruteForceTrackerIgnorePatternTest {

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
        LifecycleService ls = mock(LifecycleService.class);
        when(hazelcast.getLifecycleService()).thenReturn(ls);
        when(ls.isRunning()).thenReturn(true);
        when(hazelcast.<String, FailureWindow>getMap("bflp:windows")).thenReturn(windowsMap);
        when(hazelcast.<String, BannedIp>getMap("bflp:bans")).thenReturn(bansMap);

        when(windowsMap.get(anyString())).thenAnswer(inv -> windowsStore.get((String) inv.getArgument(0)));
        when(windowsMap.put(anyString(), any(FailureWindow.class), anyLong(), any(TimeUnit.class)))
                .thenAnswer(inv -> windowsStore.put(inv.getArgument(0), inv.getArgument(1)));
        when(bansMap.get(anyString())).thenAnswer(inv -> bansStore.get((String) inv.getArgument(0)));
        when(bansMap.putIfAbsent(anyString(), any(BannedIp.class), anyLong(), any(TimeUnit.class)))
                .thenAnswer(inv -> bansStore.putIfAbsent(inv.getArgument(0), inv.getArgument(1)));

        when(jcrTemplate.doExecuteWithSystemSessionAsUser(any(), anyString(), any(), any(JCRCallback.class)))
                .thenReturn(0);

        inject(tracker, "hazelcastManager", hazelcastManager);
        inject(tracker, "settingsService", settingsService);
        inject(tracker, "auditLogger", auditLogger);
        inject(tracker, "jcrTemplate", jcrTemplate);

        // Activate creates the executor and calls reconcileJcrBansOnStartup (no-op via JCR mock)
        tracker.activate();
    }

    private static void inject(Object target, String fieldName, Object value) throws Exception {
        Field f = target.getClass().getDeclaredField(fieldName);
        f.setAccessible(true);
        f.set(target, value);
    }

    private GlobalSettings settingsWithPatterns(List<String> patterns) {
        return GlobalSettings.builder()
                .activated(true)
                .whitelistIps("")
                .ignorePatterns(patterns)
                .auditLogMaxEntries(1000)
                .recidiveFactor(1.0)
                .maxBanTimeSec(86400L)
                .build();
    }

    private FailureEvent eventFor(String ip, String username) {
        return FailureEvent.builder()
                .ip(ip)
                .sourceName("test")
                .jailName("login")
                .timestampMs(System.currentTimeMillis())
                .username(username)
                .userAgent("agent")
                .requestPath("/cms/login")
                .extras(new HashMap<>())
                .build();
    }

    private JailConfig loginJail() {
        return new JailConfig("login", true, 10, 60L, 60L);
    }

    // -------------------------------------------------------------------------
    // 1. Matching username is skipped — no window increment, no audit log entry
    // -------------------------------------------------------------------------

    @Test
    public void matchingUsername_skipsCountingEntirely() {
        when(settingsService.getGlobalSettings()).thenReturn(
                settingsWithPatterns(Collections.singletonList("^service-.*")));
        when(settingsService.getJail("login")).thenReturn(loginJail());

        tracker.recordEvent(eventFor("10.0.0.1", "service-account"));

        assertThat(windowsStore).isEmpty();
        assertThat(bansStore).isEmpty();
        // No audit log event at all (failure was silently ignored)
        verify(auditLogger, never()).log(anyString(), anyString(), anyString(), anyString(), anyString());
    }

    // -------------------------------------------------------------------------
    // 2. Non-matching username proceeds to increment the window
    // -------------------------------------------------------------------------

    @Test
    public void nonMatchingUsername_proceedsToIncrementWindow() {
        when(settingsService.getGlobalSettings()).thenReturn(
                settingsWithPatterns(Collections.singletonList("^service-.*")));
        when(settingsService.getJail("login")).thenReturn(loginJail());

        tracker.recordEvent(eventFor("10.0.0.2", "alice"));

        assertThat(windowsStore).hasSize(1);
        verify(auditLogger, atLeastOnce()).log(eq(AuditLogger.EVENT_FAILURE),
                eq("10.0.0.2"), anyString(), anyString(), anyString());
    }

    // -------------------------------------------------------------------------
    // 3. Null username with a pattern: null is treated as no-match (not ignored)
    // -------------------------------------------------------------------------

    @Test
    public void nullUsername_treatedAsNoMatch_proceedsToIncrementWindow() {
        when(settingsService.getGlobalSettings()).thenReturn(
                settingsWithPatterns(Collections.singletonList("^service-.*")));
        when(settingsService.getJail("login")).thenReturn(loginJail());

        FailureEvent ev = FailureEvent.builder()
                .ip("10.0.0.3")
                .sourceName("test")
                .jailName("login")
                .timestampMs(System.currentTimeMillis())
                .username(null)
                .userAgent("agent")
                .requestPath("/cms/login")
                .extras(new HashMap<>())
                .build();

        tracker.recordEvent(ev);

        // Null username means matchesIgnorePattern returns false immediately
        assertThat(windowsStore).hasSize(1);
    }

    // -------------------------------------------------------------------------
    // 4. Empty pattern list: no ignore matching, event proceeds normally
    // -------------------------------------------------------------------------

    @Test
    public void emptyPatternList_eventProceedsNormally() {
        when(settingsService.getGlobalSettings()).thenReturn(
                settingsWithPatterns(Collections.emptyList()));
        when(settingsService.getJail("login")).thenReturn(loginJail());

        tracker.recordEvent(eventFor("10.0.0.4", "bob"));

        assertThat(windowsStore).hasSize(1);
    }

    // -------------------------------------------------------------------------
    // 5. Invalid regex pattern (syntax error) treated as NOT_MATCHED, event proceeds
    // -------------------------------------------------------------------------

    @Test
    public void invalidRegexPattern_treatedAsNotMatched_eventProceeds() {
        when(settingsService.getGlobalSettings()).thenReturn(
                settingsWithPatterns(Collections.singletonList("[invalid(regex")));
        when(settingsService.getJail("login")).thenReturn(loginJail());

        tracker.recordEvent(eventFor("10.0.0.5", "charlie"));

        assertThat(windowsStore).hasSize(1);
    }

    // -------------------------------------------------------------------------
    // 6. Multiple patterns: first match wins, second not evaluated
    // -------------------------------------------------------------------------

    @Test
    public void multiplePatterns_firstMatchWins() {
        when(settingsService.getGlobalSettings()).thenReturn(
                settingsWithPatterns(Arrays.asList("^admin$", "^service-.*")));
        when(settingsService.getJail("login")).thenReturn(loginJail());

        tracker.recordEvent(eventFor("10.0.0.6", "admin"));

        assertThat(windowsStore).isEmpty();
    }

    // -------------------------------------------------------------------------
    // 7. Catastrophic-backtracking pattern triggers fail-closed (treated as MATCHED)
    //    Use a real ReDoS pattern with a long input that will timeout in 50ms.
    //    We verify the event is silently dropped (fail-closed = treated as a match).
    // -------------------------------------------------------------------------

    @Test
    @SuppressWarnings("unchecked")
    public void catastrophicRegex_failClosed_eventSkipped() throws Exception {
        // Deterministically exercise the fail-closed contract: when matching a pattern
        // exceeds the timeout, evaluateIgnorePattern catches TimeoutException and treats
        // the pattern as MATCHED, so the username is "ignored" and no window entry is
        // created. Rather than racing a real ReDoS (timing/JIT-dependent), inject a stub
        // executor whose Future.get(timeout) throws TimeoutException.
        ExecutorService timingOutExecutor = mock(ExecutorService.class);
        Future<Boolean> timingOutFuture = mock(Future.class);
        when(timingOutFuture.get(anyLong(), any(TimeUnit.class)))
                .thenThrow(new TimeoutException("forced timeout"));
        when(timingOutExecutor.submit(any(Callable.class))).thenReturn((Future) timingOutFuture);
        inject(tracker, "ignorePatternExecutor", timingOutExecutor);

        when(settingsService.getGlobalSettings()).thenReturn(
                settingsWithPatterns(Collections.singletonList("(a+)+")));
        when(settingsService.getJail("login")).thenReturn(loginJail());

        tracker.recordEvent(eventFor("10.0.0.7", "aaaaaaaaaab"));

        // Fail-closed: the event was dropped before the window increment.
        assertThat(windowsStore).isEmpty();
    }
}
