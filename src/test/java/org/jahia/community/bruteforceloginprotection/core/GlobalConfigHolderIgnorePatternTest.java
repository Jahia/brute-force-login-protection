package org.jahia.community.bruteforceloginprotection.core;

import org.junit.Test;

import java.util.Dictionary;
import java.util.Hashtable;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for the ignore-pattern safety filter applied by
 * {@link GlobalConfigHolder#fromDictionary(Dictionary)}.
 *
 * <p>The GraphQL save path lints patterns before persisting them, but the {@code .cfg} is a
 * documented hand-edit surface ("Edit and Felix file-install will reload the values without a
 * restart"), so the save-time lint is bypassable. The load path applies the same lint and drops
 * offending entries. No OSGi container needed.
 */
public class GlobalConfigHolderIgnorePatternTest {

    private static Dictionary<String, Object> dictWithPatterns(String csv) {
        Hashtable<String, Object> d = new Hashtable<>();
        d.put(GlobalConfigHolder.CFG_IGNORE_PATTERNS, csv);
        return d;
    }

    @Test
    public void fromDictionary_unsafeIgnorePattern_isDroppedAndSafeOnesKept() {
        GlobalSettings s = GlobalConfigHolder.fromDictionary(
                dictWithPatterns("^service-.*$,(.*a){20},^batch-.*$"));

        // Dropping is the fail-safe direction: an exemption fewer means the login failures it
        // would have hidden are counted.
        assertThat(s.getIgnorePatterns()).containsExactly("^service-.*$", "^batch-.*$");
    }

    @Test
    public void fromDictionary_invalidRegexSyntax_isDropped() {
        assertThat(GlobalConfigHolder.fromDictionary(dictWithPatterns("[unclosed")).getIgnorePatterns())
                .isEmpty();
    }

    @Test
    public void fromDictionary_overLengthPattern_isDropped() {
        StringBuilder tooLong = new StringBuilder();
        for (int i = 0; i < RegexSafetyCheck.MAX_PATTERN_LENGTH + 1; i++) {
            tooLong.append('a');
        }
        assertThat(GlobalConfigHolder.fromDictionary(dictWithPatterns(tooLong.toString())).getIgnorePatterns())
                .isEmpty();
    }

    @Test
    public void fromDictionary_allSafePatterns_areKept() {
        // Pins that the filter is not over-eager: a legitimate config must survive untouched.
        GlobalSettings s = GlobalConfigHolder.fromDictionary(
                dictWithPatterns("^service-.*$,(admin|root),^jenkins-agent-[0-9]+$"));
        assertThat(s.getIgnorePatterns())
                .containsExactly("^service-.*$", "(admin|root)", "^jenkins-agent-[0-9]+$");
    }

    @Test
    public void fromDictionary_everyPatternUnsafe_yieldsEmptyListNotDefaults() {
        // The decisive case. If the filter threw instead of dropping, updated() would abort before
        // current.set(...) and the holder would keep serving defaults() -- which has
        // activated=false. A ReDoS lint whose failure mode is "brute-force protection silently
        // turned itself off" would be the same inverted reasoning that caused GHSA-7qgr-2hqv-r344.
        Hashtable<String, Object> d = new Hashtable<>();
        d.put(GlobalConfigHolder.CFG_IGNORE_PATTERNS, "(.*a){20},(b+){9}");
        d.put(GlobalConfigHolder.CFG_ACTIVATED, "true");

        GlobalSettings s = GlobalConfigHolder.fromDictionary(d);

        assertThat(s.getIgnorePatterns()).isEmpty();
        assertThat(s.isActivated()).isTrue();
    }

    @Test
    public void fromDictionary_noIgnorePatternsKey_yieldsEmptyList() {
        assertThat(GlobalConfigHolder.fromDictionary(new Hashtable<>()).getIgnorePatterns()).isEmpty();
    }
}
