package org.jahia.community.bruteforceloginprotection.core;

import org.junit.Before;
import org.junit.Test;
import org.osgi.service.cm.Configuration;
import org.osgi.service.cm.ConfigurationAdmin;

import java.lang.reflect.Field;
import java.util.Dictionary;
import java.util.Hashtable;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * F22 — {@link SettingsService#saveGlobalSettings}/{@link SettingsService#saveJail}/
 * {@link SettingsService#deleteJail} driven against a mocked {@link ConfigurationAdmin}, without
 * any live OSGi/JCR runtime.
 */
public class SettingsServiceSaveTest {

    private SettingsService settingsService;
    private ConfigurationAdmin configurationAdmin;

    @Before
    public void setUp() throws Exception {
        settingsService = new SettingsService();
        configurationAdmin = mock(ConfigurationAdmin.class);
        inject(settingsService, "configurationAdmin", configurationAdmin);
    }

    private static void inject(Object target, String field, Object value) throws Exception {
        Field f = target.getClass().getDeclaredField(field);
        f.setAccessible(true);
        f.set(target, value);
    }

    private static Configuration mockConfigWithProps() throws Exception {
        Configuration cfg = mock(Configuration.class);
        Hashtable<String, Object> props = new Hashtable<>();
        when(cfg.getProperties()).thenReturn(props);
        return cfg;
    }

    // -------------------------------------------------------------------------------------------
    // saveGlobalSettings
    // -------------------------------------------------------------------------------------------

    @Test
    public void saveGlobalSettingsWritesExpectedKeysAndCallsUpdateOnce() throws Exception {
        Configuration cfg = mockConfigWithProps();
        when(configurationAdmin.getConfiguration(GlobalConfigHolder.PID, "?")).thenReturn(cfg);

        GlobalSettingsUpdate update = GlobalSettingsUpdate.builder()
                .activated(true)
                .whitelistIps("10.0.0.0/8")
                .auditLogMaxEntries(500)
                .recidiveFactor(3.0)
                .maxBanTimeSeconds(3600)
                .build();

        boolean result = settingsService.saveGlobalSettings(update);

        assertThat(result).isTrue();
        @SuppressWarnings("unchecked")
        org.mockito.ArgumentCaptor<Dictionary<String, Object>> captor =
                org.mockito.ArgumentCaptor.forClass((Class) Dictionary.class);
        verify(cfg, times(1)).update(captor.capture());
        Dictionary<String, Object> written = captor.getValue();
        assertThat(written.get(GlobalConfigHolder.CFG_ACTIVATED)).isEqualTo("true");
        assertThat(written.get(GlobalConfigHolder.CFG_WHITELIST)).isEqualTo("10.0.0.0/8");
        assertThat(written.get(GlobalConfigHolder.CFG_AUDIT_LOG_MAX)).isEqualTo("500");
        assertThat(written.get(GlobalConfigHolder.CFG_RECIDIVE_FACTOR)).isEqualTo("3.0");
        assertThat(written.get(GlobalConfigHolder.CFG_MAX_BAN_TIME_SEC)).isEqualTo("3600");
    }

    @Test
    public void saveGlobalSettingsReturnsFalseWhenConfigurationAdminMissing() throws Exception {
        inject(settingsService, "configurationAdmin", null);
        assertThat(settingsService.saveGlobalSettings(GlobalSettingsUpdate.builder().build())).isFalse();
    }

    @Test
    public void saveGlobalSettingsReturnsFalseForNullUpdate() {
        assertThat(settingsService.saveGlobalSettings(null)).isFalse();
    }

    // -------------------------------------------------------------------------------------------
    // saveJail — new vs existing, unsafe name rejection
    // -------------------------------------------------------------------------------------------

    @Test
    public void saveJailCreatesNewFactoryConfigurationWhenNoneExists() throws Exception {
        when(configurationAdmin.listConfigurations(anyString())).thenReturn(null);
        Configuration created = mockConfigWithProps();
        when(configurationAdmin.createFactoryConfiguration(JailConfigTracker.FACTORY_PID, "?")).thenReturn(created);

        boolean result = settingsService.saveJail("login2", true, 5, 600, 1800);

        assertThat(result).isTrue();
        verify(configurationAdmin).createFactoryConfiguration(JailConfigTracker.FACTORY_PID, "?");
        verify(created).update(any());
        assertThat(created.getProperties().get(JailConfigTracker.CFG_NAME)).isEqualTo("login2");
        assertThat(created.getProperties().get(JailConfigTracker.CFG_MAX_RETRY)).isEqualTo("5");
    }

    @Test
    public void saveJailReusesExistingConfigurationWhenFoundByNameFilter() throws Exception {
        Configuration existing = mockConfigWithProps();
        when(configurationAdmin.listConfigurations(anyString())).thenReturn(new Configuration[]{existing});

        boolean result = settingsService.saveJail("login2", true, 7, 700, 2100);

        assertThat(result).isTrue();
        verify(configurationAdmin, never()).createFactoryConfiguration(anyString(), anyString());
        verify(existing).update(any());
        assertThat(existing.getProperties().get(JailConfigTracker.CFG_MAX_RETRY)).isEqualTo("7");
    }

    @Test
    public void saveJailRejectsUnsafeNameWithoutTouchingConfigurationAdmin() throws Exception {
        boolean result = settingsService.saveJail("../etc/passwd", true, 5, 600, 1800);

        assertThat(result).isFalse();
        verify(configurationAdmin, never()).listConfigurations(anyString());
        verify(configurationAdmin, never()).createFactoryConfiguration(anyString(), anyString());
    }

    @Test
    public void saveJailRejectsOutOfRangeNumericFields() throws Exception {
        boolean result = settingsService.saveJail("login2", true, 999_999_999, 600, 1800);

        assertThat(result).isFalse();
        verify(configurationAdmin, never()).listConfigurations(anyString());
    }

    // -------------------------------------------------------------------------------------------
    // deleteJail
    // -------------------------------------------------------------------------------------------

    @Test
    public void deleteJailDeletesFoundConfiguration() throws Exception {
        Configuration existing = mock(Configuration.class);
        when(configurationAdmin.listConfigurations(anyString())).thenReturn(new Configuration[]{existing});

        boolean result = settingsService.deleteJail("login2");

        assertThat(result).isTrue();
        verify(existing).delete();
    }

    @Test
    public void deleteJailRejectsUnsafeName() throws Exception {
        assertThat(settingsService.deleteJail("foo/bar")).isFalse();
        verify(configurationAdmin, never()).listConfigurations(anyString());
    }

    @Test
    public void deleteJailOnMissingConfigurationStillReturnsTrue() throws Exception {
        when(configurationAdmin.listConfigurations(anyString())).thenReturn(null);
        assertThat(settingsService.deleteJail("login2")).isTrue();
    }
}
