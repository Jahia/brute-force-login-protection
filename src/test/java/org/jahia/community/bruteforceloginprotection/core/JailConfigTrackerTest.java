package org.jahia.community.bruteforceloginprotection.core;

import org.junit.Test;
import org.osgi.service.cm.ConfigurationException;

import java.util.Hashtable;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.jahia.community.bruteforceloginprotection.BruteForceLoginProtectionConstants.DEFAULT_BAN_TIME_SEC;
import static org.jahia.community.bruteforceloginprotection.BruteForceLoginProtectionConstants.DEFAULT_FIND_TIME_SEC;
import static org.jahia.community.bruteforceloginprotection.BruteForceLoginProtectionConstants.DEFAULT_JAIL_LOGIN;
import static org.jahia.community.bruteforceloginprotection.BruteForceLoginProtectionConstants.DEFAULT_MAX_RETRY;

/**
 * Unit tests for {@link JailConfigTracker}: F2-a (CRUD/persistence/rename-eviction), U6
 * (path-traversal guard on jail names) and U7 (synthetic default-jail fallback).
 */
public class JailConfigTrackerTest {

    private static Hashtable<String, Object> props(String name, boolean enabled, int maxRetry, long findTime, long banTime) {
        Hashtable<String, Object> p = new Hashtable<>();
        p.put(JailConfigTracker.CFG_NAME, name);
        p.put(JailConfigTracker.CFG_ENABLED, enabled);
        p.put(JailConfigTracker.CFG_MAX_RETRY, maxRetry);
        p.put(JailConfigTracker.CFG_FIND_TIME, findTime);
        p.put(JailConfigTracker.CFG_BAN_TIME, banTime);
        return p;
    }

    // -------------------------------------------------------------------------------------------
    // F2-a — CRUD, persistence
    // -------------------------------------------------------------------------------------------

    @Test
    public void updatedThenGetJailReturnsPersistedFields() throws Exception {
        JailConfigTracker tracker = new JailConfigTracker();
        tracker.updated("pid-1", props("login2", true, 5, 600, 1800));

        JailConfig jc = tracker.getJail("login2");
        assertThat(jc.getName()).isEqualTo("login2");
        assertThat(jc.isEnabled()).isTrue();
        assertThat(jc.getMaxRetry()).isEqualTo(5);
        assertThat(jc.getFindTimeSec()).isEqualTo(600);
        assertThat(jc.getBanTimeSec()).isEqualTo(1800);
        assertThat(tracker.getJails()).containsKey("login2");
        assertThat(tracker.hasJail("login2")).isTrue();
    }

    @Test
    public void deletedRemovesJail() throws Exception {
        JailConfigTracker tracker = new JailConfigTracker();
        tracker.updated("pid-1", props("login2", true, 5, 600, 1800));
        assertThat(tracker.getJails()).containsKey("login2");

        tracker.deleted("pid-1");

        assertThat(tracker.getJails()).doesNotContainKey("login2");
        assertThat(tracker.hasJail("login2")).isFalse();
    }

    @Test
    public void updatedWithNullPropertiesDelegatesToDeleted() throws Exception {
        JailConfigTracker tracker = new JailConfigTracker();
        tracker.updated("pid-1", props("login2", true, 5, 600, 1800));

        tracker.updated("pid-1", null);

        assertThat(tracker.getJails()).doesNotContainKey("login2");
    }

    @Test
    public void renamingSamePidEvictsPreviousName() throws Exception {
        JailConfigTracker tracker = new JailConfigTracker();
        tracker.updated("pid-1", props("old-name", true, 5, 600, 1800));
        assertThat(tracker.getJails()).containsKey("old-name");

        tracker.updated("pid-1", props("new-name", true, 5, 600, 1800));

        assertThat(tracker.getJails()).containsKey("new-name");
        assertThat(tracker.getJails()).doesNotContainKey("old-name");
        assertThat(tracker.findPidByName("new-name")).isEqualTo("pid-1");
        assertThat(tracker.findPidByName("old-name")).isNull();
    }

    @Test
    public void blankOrUnsafeNameRejectedAtUpdate() {
        JailConfigTracker tracker = new JailConfigTracker();
        assertThatThrownBy(() -> tracker.updated("pid-1", props("", true, 5, 600, 1800)))
                .isInstanceOf(ConfigurationException.class);
        assertThatThrownBy(() -> tracker.updated("pid-2", props("../etc/passwd", true, 5, 600, 1800)))
                .isInstanceOf(ConfigurationException.class);
    }

    // -------------------------------------------------------------------------------------------
    // U6 — jail-name path-traversal guard
    // -------------------------------------------------------------------------------------------

    @Test
    public void isUnsafeJailNameRejectsTraversalAndSeparators() {
        assertThat(JailConfigTracker.isUnsafeJailName("../etc/passwd")).isTrue();
        assertThat(JailConfigTracker.isUnsafeJailName("foo/bar")).isTrue();
        assertThat(JailConfigTracker.isUnsafeJailName("foo\\bar")).isTrue();
        assertThat(JailConfigTracker.isUnsafeJailName("foo:bar")).isTrue();
        assertThat(JailConfigTracker.isUnsafeJailName(null)).isTrue();
    }

    @Test
    public void isUnsafeJailNameAcceptsOrdinaryName() {
        assertThat(JailConfigTracker.isUnsafeJailName("login-2")).isFalse();
    }

    // -------------------------------------------------------------------------------------------
    // U7 — synthetic default-jail fallback
    // -------------------------------------------------------------------------------------------

    @Test
    public void getJailForUnknownNameSynthesizesDefault() throws Exception {
        JailConfigTracker tracker = new JailConfigTracker();
        tracker.updated("pid-1", props(DEFAULT_JAIL_LOGIN, true, 3, 300, 900));

        JailConfig jc = tracker.getJail("typo-name");

        assertThat(jc).isNotNull();
        assertThat(jc.getName()).isEqualTo("typo-name");
        assertThat(jc.isEnabled()).isTrue();
        assertThat(jc.getMaxRetry()).isEqualTo(DEFAULT_MAX_RETRY);
        assertThat(jc.getFindTimeSec()).isEqualTo(DEFAULT_FIND_TIME_SEC);
        assertThat(jc.getBanTimeSec()).isEqualTo(DEFAULT_BAN_TIME_SEC);
        // Never registered, so hasJail must distinguish "resolves via default" from "configured".
        assertThat(tracker.hasJail("typo-name")).isFalse();
    }

    @Test
    public void getJailsOnEmptyTrackerSynthesizesBuiltinLoginJail() {
        JailConfigTracker tracker = new JailConfigTracker();

        assertThat(tracker.getJails()).containsKey(DEFAULT_JAIL_LOGIN);
        JailConfig login = tracker.getJails().get(DEFAULT_JAIL_LOGIN);
        assertThat(login.getMaxRetry()).isEqualTo(DEFAULT_MAX_RETRY);
        assertThat(tracker.hasJail(DEFAULT_JAIL_LOGIN)).isFalse();
    }
}
