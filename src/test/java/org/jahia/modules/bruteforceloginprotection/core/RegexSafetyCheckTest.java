package org.jahia.modules.bruteforceloginprotection.core;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link RegexSafetyCheck}, the ReDoS lint applied to user-supplied
 * {@code ignorePatterns}. Covers length, syntax, nested-quantifier, per-group quantifier
 * density and group-nesting-depth (hardened) rejections, plus acceptance of safe patterns.
 */
public class RegexSafetyCheckTest {

    @Test
    public void nullPatternIsAllowed() {
        assertThatCode(() -> RegexSafetyCheck.assertSafe(null)).doesNotThrowAnyException();
    }

    @Test
    public void simpleValidPatternsAreAccepted() {
        assertThatCode(() -> RegexSafetyCheck.assertSafe("^admin[0-9]{2,4}$")).doesNotThrowAnyException();
        assertThatCode(() -> RegexSafetyCheck.assertSafe("([a-z]+_)[0-9]+")).doesNotThrowAnyException();
    }

    @Test
    public void overLengthPatternRejected() {
        String tooLong = repeat("a", RegexSafetyCheck.MAX_PATTERN_LENGTH + 1);
        assertThatThrownBy(() -> RegexSafetyCheck.assertSafe(tooLong))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("exceeds");
    }

    @Test
    public void patternAtMaxLengthAccepted() {
        assertThatCode(() -> RegexSafetyCheck.assertSafe(repeat("a", RegexSafetyCheck.MAX_PATTERN_LENGTH)))
                .doesNotThrowAnyException();
    }

    @Test
    public void invalidRegexSyntaxRejected() {
        assertThatThrownBy(() -> RegexSafetyCheck.assertSafe("(unclosed["))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid regex");
    }

    @Test
    public void nestedQuantifierDoubleStackRejected_star() {
        // group-close followed by two stacked quantifiers
        assertThatThrownBy(() -> RegexSafetyCheck.assertSafe("(x)*+"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    public void nestedQuantifierDoubleStackRejected_plus() {
        assertThatThrownBy(() -> RegexSafetyCheck.assertSafe("(y)++"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    public void nestedQuantifierSingleQuantifierOnGroupRejected() {
        // (a+)+ is the canonical catastrophic-backtracking (ReDoS) pattern
        assertThatThrownBy(() -> RegexSafetyCheck.assertSafe("(a+)+"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    public void nestedQuantifierSingleQuantifierOnGroupRejected_star() {
        assertThatThrownBy(() -> RegexSafetyCheck.assertSafe("(a+)*"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    public void excessiveQuantifierDensityWithinGroupRejected() {
        assertThatThrownBy(() -> RegexSafetyCheck.assertSafe("(a+b*c+d*)"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("quantifiers");
    }

    @Test
    public void excessiveGroupNestingRejected() {
        // Hardening: nesting beyond MAX_GROUP_DEPTH is rejected outright rather than silently
        // bypassing the per-group quantifier check.
        int depth = RegexSafetyCheck.MAX_GROUP_DEPTH + 1;
        String deeplyNested = repeat("(", depth) + "a" + repeat(")", depth);
        assertThatThrownBy(() -> RegexSafetyCheck.assertSafe(deeplyNested))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("nesting");
    }

    @Test
    public void moderateGroupNestingAccepted() {
        assertThatCode(() -> RegexSafetyCheck.assertSafe("(((((a)))))")).doesNotThrowAnyException();
    }

    private static String repeat(String s, int n) {
        StringBuilder sb = new StringBuilder(s.length() * n);
        for (int i = 0; i < n; i++) {
            sb.append(s);
        }
        return sb.toString();
    }
}
