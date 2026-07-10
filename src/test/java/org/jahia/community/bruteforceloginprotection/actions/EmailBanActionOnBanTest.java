package org.jahia.community.bruteforceloginprotection.actions;

import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.core.IMap;
import org.jahia.community.bruteforceloginprotection.core.BanContext;
import org.jahia.community.bruteforceloginprotection.core.GlobalSettings;
import org.jahia.community.bruteforceloginprotection.core.IntegrationTestResult;
import org.jahia.community.bruteforceloginprotection.core.SettingsService;
import org.jahia.community.bruteforceloginprotection.hazelcast.HazelcastInstanceManager;
import org.jahia.services.mail.MailService;
import org.junit.Before;
import org.junit.Test;

import java.lang.reflect.Field;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.jahia.community.bruteforceloginprotection.BruteForceLoginProtectionConstants.MAP_NOTIFICATION_MARKERS;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * F6-b — {@link EmailBanAction#onBan} sends a per-IP-throttled ban-notification email.
 * D4 (email half) — {@link EmailBanAction#sendTest()} bypasses that throttle entirely, so two
 * back-to-back calls both actually attempt to send (in contrast to onBan()'s throttled path).
 *
 * MailService.getInstance() is a static factory; EmailBanAction#resolveMailService() is a small
 * package-private seam (added for this test) that a spy can override without needing to mock a
 * static method.
 */
public class EmailBanActionOnBanTest {

    private EmailBanAction action;
    private SettingsService settingsService;
    private MailService mailService;
    private java.util.Map<String, Long> notifStore;

    @Before
    public void setUp() throws Exception {
        action = spy(new EmailBanAction());
        settingsService = mock(SettingsService.class);
        HazelcastInstanceManager hazelcastManager = mock(HazelcastInstanceManager.class);
        HazelcastInstance hazelcast = mock(HazelcastInstance.class);
        mailService = mock(MailService.class);

        notifStore = new ConcurrentHashMap<>();
        @SuppressWarnings("unchecked")
        IMap<String, Long> notifMap = mock(IMap.class);
        when(notifMap.putIfAbsent(anyString(), anyLong(), anyLong(), any(TimeUnit.class)))
                .thenAnswer(inv -> notifStore.putIfAbsent(inv.getArgument(0), inv.getArgument(1)));
        when(hazelcastManager.getHazelcastInstance()).thenReturn(hazelcast);
        when(hazelcast.<String, Long>getMap(MAP_NOTIFICATION_MARKERS)).thenReturn(notifMap);

        when(mailService.isEnabled()).thenReturn(true);
        when(mailService.defaultRecipient()).thenReturn("ops@example.com");
        when(mailService.defaultSender()).thenReturn("bflp@example.com");
        doReturn(mailService).when(action).resolveMailService();

        inject(action, "settingsService", settingsService);
        inject(action, "hazelcastManager", hazelcastManager);
    }

    private static void inject(Object target, String field, Object value) throws Exception {
        Field f = target.getClass().getDeclaredField(field);
        f.setAccessible(true);
        f.set(target, value);
    }

    private BanContext banContext(String ip) {
        return BanContext.builder()
                .ip(ip)
                .jailName("login")
                .sourceName("test-source")
                .bannedAt(System.currentTimeMillis())
                .bannedUntil(System.currentTimeMillis() + 60_000L)
                .banCount(1)
                .reason("test")
                .build();
    }

    // -------------------------------------------------------------------------------------------
    // F6-b — throttled onBan()
    // -------------------------------------------------------------------------------------------

    @Test
    public void onBanSendsEmailWhenEnabled() {
        when(settingsService.getGlobalSettings()).thenReturn(GlobalSettings.builder()
                .emailEnabled(true)
                .emailRecipient("admin@example.com")
                .build());

        action.onBan(banContext("1.2.3.4"));

        verify(mailService, times(1)).sendMessage(anyString(), anyString(), any(), any(), anyString(), anyString());
    }

    @Test
    public void onBanSkipsSendWhenEmailDisabled() {
        when(settingsService.getGlobalSettings()).thenReturn(GlobalSettings.builder()
                .emailEnabled(false)
                .build());

        action.onBan(banContext("1.2.3.4"));

        verify(mailService, never()).sendMessage(anyString(), anyString(), any(), any(), anyString(), anyString());
    }

    @Test
    public void secondOnBanWithinThrottleWindowForSameIpIsSuppressed() {
        when(settingsService.getGlobalSettings()).thenReturn(GlobalSettings.builder()
                .emailEnabled(true)
                .emailRecipient("admin@example.com")
                .build());

        action.onBan(banContext("2.2.2.2"));
        action.onBan(banContext("2.2.2.2"));

        // Only the FIRST call within the notification-throttle window actually sends.
        verify(mailService, times(1)).sendMessage(anyString(), anyString(), any(), any(), anyString(), anyString());
    }

    @Test
    public void onBanForDifferentIpsBothSend() {
        when(settingsService.getGlobalSettings()).thenReturn(GlobalSettings.builder()
                .emailEnabled(true)
                .emailRecipient("admin@example.com")
                .build());

        action.onBan(banContext("3.3.3.1"));
        action.onBan(banContext("3.3.3.2"));

        verify(mailService, times(2)).sendMessage(anyString(), anyString(), any(), any(), anyString(), anyString());
    }

    // -------------------------------------------------------------------------------------------
    // D4 — sendTest() bypasses the per-IP throttle entirely: two sequential calls both attempt
    // to send, unlike onBan()'s throttled path proven above.
    // -------------------------------------------------------------------------------------------

    @Test
    public void sendTestCalledTwiceSequentially_bothActuallyAttemptToSend() {
        when(settingsService.getGlobalSettings()).thenReturn(GlobalSettings.builder()
                .emailRecipient("admin@example.com")
                .build());

        IntegrationTestResult first = action.sendTest();
        IntegrationTestResult second = action.sendTest();

        assertThat(first.success()).isTrue();
        assertThat(second.success()).isTrue();
        verify(mailService, times(2)).sendMessage(anyString(), anyString(), any(), any(), anyString(), anyString());
    }
}
