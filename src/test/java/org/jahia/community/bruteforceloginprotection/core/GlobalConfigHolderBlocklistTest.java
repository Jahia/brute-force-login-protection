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

    // -------------------------------------------------------------------------------------------
    // F25 — v2.x -> v3.0.0 breaking migration: legacy JCR property names are silently ignored,
    // never read, by the current OSGi-config-based parser. Regression guard against a future
    // refactor accidentally reintroducing a v2-key read path (no automatic migration by design).
    // -------------------------------------------------------------------------------------------

    @Test
    public void fromDictionary_legacyV2KeysAreIgnored_fallBackToDefaults() {
        Dictionary<String, Object> d = new Hashtable<>();
        // Legacy v2.x keys -- none of the current GlobalConfigHolder.CFG_* names.
        d.put("nb_failed_login_max", "3");
        d.put("time_to_idle", "600");

        GlobalSettings s = GlobalConfigHolder.fromDictionary(d);
        GlobalSettings defaults = GlobalConfigHolder.defaults();

        // Every field falls back to its documented default, exactly as if the dictionary had been
        // empty -- the legacy keys are never read.
        assertThat(s.isActivated()).isEqualTo(defaults.isActivated());
        assertThat(s.getWhitelistIps()).isEqualTo(defaults.getWhitelistIps());
        assertThat(s.getAuditLogMaxEntries()).isEqualTo(defaults.getAuditLogMaxEntries());
        assertThat(s.getRecidiveFactor()).isEqualTo(defaults.getRecidiveFactor());
        assertThat(s.getMaxBanTimeSec()).isEqualTo(defaults.getMaxBanTimeSec());
        assertThat(s.isTorBlocklistEnabled()).isEqualTo(defaults.isTorBlocklistEnabled());
        assertThat(s.getTorBlocklistUrl()).isEqualTo(defaults.getTorBlocklistUrl());
    }
}
