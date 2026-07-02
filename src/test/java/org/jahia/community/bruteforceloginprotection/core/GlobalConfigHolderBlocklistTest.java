package org.jahia.community.bruteforceloginprotection.core;

import org.junit.Test;

import java.util.Dictionary;
import java.util.Hashtable;

import static org.assertj.core.api.Assertions.assertThat;
import static org.jahia.community.bruteforceloginprotection.BruteForceLoginProtectionConstants.DEFAULT_TOR_BLOCKLIST_URL;
import static org.jahia.community.bruteforceloginprotection.BruteForceLoginProtectionConstants.DEFAULT_TOR_REFRESH_SEC;
import static org.jahia.community.bruteforceloginprotection.BruteForceLoginProtectionConstants.MIN_TOR_REFRESH_SEC;

/**
 * Unit tests for the blocklist-related keys of {@link GlobalConfigHolder#fromDictionary(Dictionary)}
 * and {@link GlobalConfigHolder#defaults()}. No OSGi container needed.
 */
public class GlobalConfigHolderBlocklistTest {

    // -------------------------------------------------------------------------
    // Defaults
    // -------------------------------------------------------------------------

    @Test
    public void defaults_blocklistDisabledAndEmpty() {
        GlobalSettings s = GlobalConfigHolder.defaults();
        assertThat(s.getBlocklistIps()).isNull();
        assertThat(s.isTorBlocklistEnabled()).isFalse();
        assertThat(s.getTorBlocklistUrl()).isEqualTo(DEFAULT_TOR_BLOCKLIST_URL);
        assertThat(s.getTorBlocklistRefreshSeconds()).isEqualTo(DEFAULT_TOR_REFRESH_SEC);
    }

    @Test
    public void fromDictionary_missingKeys_fallBackToDefaults() {
        GlobalSettings s = GlobalConfigHolder.fromDictionary(new Hashtable<>());
        assertThat(s.getBlocklistIps()).isNull();
        assertThat(s.isTorBlocklistEnabled()).isFalse();
        assertThat(s.getTorBlocklistUrl()).isEqualTo(DEFAULT_TOR_BLOCKLIST_URL);
        assertThat(s.getTorBlocklistRefreshSeconds()).isEqualTo(DEFAULT_TOR_REFRESH_SEC);
    }

    // -------------------------------------------------------------------------
    // Parsing
    // -------------------------------------------------------------------------

    @Test
    public void fromDictionary_parsesBlocklistKeys() {
        Dictionary<String, Object> d = new Hashtable<>();
        d.put(GlobalConfigHolder.CFG_BLOCKLIST, "203.0.113.0/24,198.51.100.1/32");
        d.put(GlobalConfigHolder.CFG_TOR_ENABLED, "true");
        d.put(GlobalConfigHolder.CFG_TOR_URL, "http://mirror.internal/exit-addresses");
        d.put(GlobalConfigHolder.CFG_TOR_REFRESH_SEC, "7200");

        GlobalSettings s = GlobalConfigHolder.fromDictionary(d);

        assertThat(s.getBlocklistIps()).isEqualTo("203.0.113.0/24,198.51.100.1/32");
        assertThat(s.isTorBlocklistEnabled()).isTrue();
        assertThat(s.getTorBlocklistUrl()).isEqualTo("http://mirror.internal/exit-addresses");
        assertThat(s.getTorBlocklistRefreshSeconds()).isEqualTo(7200L);
    }

    @Test
    public void fromDictionary_blankTorUrl_fallsBackToDefault() {
        Dictionary<String, Object> d = new Hashtable<>();
        d.put(GlobalConfigHolder.CFG_TOR_URL, "  ");

        GlobalSettings s = GlobalConfigHolder.fromDictionary(d);

        assertThat(s.getTorBlocklistUrl()).isEqualTo(DEFAULT_TOR_BLOCKLIST_URL);
    }

    // -------------------------------------------------------------------------
    // Refresh clamping (defensive against hand-edited .cfg)
    // -------------------------------------------------------------------------

    @Test
    public void fromDictionary_refreshBelowMinimum_clampedUp() {
        Dictionary<String, Object> d = new Hashtable<>();
        d.put(GlobalConfigHolder.CFG_TOR_REFRESH_SEC, "10");

        GlobalSettings s = GlobalConfigHolder.fromDictionary(d);

        assertThat(s.getTorBlocklistRefreshSeconds()).isEqualTo(MIN_TOR_REFRESH_SEC);
    }

    @Test
    public void fromDictionary_refreshGarbage_fallsBackToDefault() {
        Dictionary<String, Object> d = new Hashtable<>();
        d.put(GlobalConfigHolder.CFG_TOR_REFRESH_SEC, "not-a-number");

        GlobalSettings s = GlobalConfigHolder.fromDictionary(d);

        assertThat(s.getTorBlocklistRefreshSeconds()).isEqualTo(DEFAULT_TOR_REFRESH_SEC);
    }
}
