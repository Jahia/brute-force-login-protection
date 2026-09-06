package org.jahia.community.bruteforceloginprotection.core;

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
    public void escapedClosingParenFollowedByQuantifierAccepted() {
        // \)+ matches a literal ')' character one or more times — not a group close.
        // The preceding backslash escapes ')', so this must NOT be flagged as a nested quantifier.
        assertThatCode(() -> RegexSafetyCheck.assertSafe("\\)+")).doesNotThrowAnyException();
    }

    @Test
    public void escapedClosingParenInLargerPatternAccepted() {
        // \d+\)? — one-or-more digits optionally followed by a literal ')'. Safe pattern.
        assertThatCode(() -> RegexSafetyCheck.assertSafe("\\d+\\)?")).doesNotThrowAnyException();
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

    // -------------------------------------------------------------------------------------------
    // Bounded repetition over a group containing an unbounded quantifier.
    //
    // This is the shape that actually backtracks on Java's engine. Measured on JDK 17 with
    // Matcher.matches() against "a"*n + "b":
    //
    //     (.*a){20}   n=20  60ms   n=24  649ms   n=28  8.2s   n=30  27s   n=32  101s
    //     ^(a+)+$     n=20   0ms   n=24    0ms   n=28    0ms  n=30   0ms  n=32   0ms
    //
    // The textbook nested-quantifier forms this lint has always rejected are optimised away by
    // Java and cost nothing; the shape below was accepted until now. GHSA-7qgr-2hqv-r344 used
    // exactly (.*a){20}.
    // -------------------------------------------------------------------------------------------

    @Test
    public void quantifiedGroupWithInnerStarRejected() {
        assertThatThrownBy(() -> RegexSafetyCheck.assertSafe("(.*a){20}"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("unbounded quantifier");
    }

    @Test
    public void quantifiedGroupWithInnerPlusRejected() {
        assertThatThrownBy(() -> RegexSafetyCheck.assertSafe("(a+){10}"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("unbounded quantifier");
    }

    @Test
    public void quantifiedGroupWithOnlyBoundedInnerQuantifiersAccepted() {
        // ([0-9]{2}){3} repeats a group, but the inner quantifier is bounded, so the state space
        // stays finite. Measured 0ms. Rejecting it would be a false positive on a shape operators
        // legitimately write for fixed-width identifiers.
        assertThatCode(() -> RegexSafetyCheck.assertSafe("([0-9]{2}){3}")).doesNotThrowAnyException();
        assertThatCode(() -> RegexSafetyCheck.assertSafe("(abc){3}")).doesNotThrowAnyException();
        assertThatCode(() -> RegexSafetyCheck.assertSafe("(https?){2}")).doesNotThrowAnyException();
    }

    @Test
    public void legitimateOperatorPatternsAccepted() {
        // Blast-radius contract for the rule above: these are the shapes real operators write for
        // service accounts and monitoring principals. None may start being rejected.
        assertThatCode(() -> RegexSafetyCheck.assertSafe("^service-.*$")).doesNotThrowAnyException();
        assertThatCode(() -> RegexSafetyCheck.assertSafe("(admin|root)")).doesNotThrowAnyException();
        assertThatCode(() -> RegexSafetyCheck.assertSafe("^(svc|api)-account$")).doesNotThrowAnyException();
        assertThatCode(() -> RegexSafetyCheck.assertSafe("^admin[0-9]{2,4}$")).doesNotThrowAnyException();
        assertThatCode(() -> RegexSafetyCheck.assertSafe("([a-z]+_)[0-9]+")).doesNotThrowAnyException();
        assertThatCode(() -> RegexSafetyCheck.assertSafe("^jenkins-agent-[0-9]+$")).doesNotThrowAnyException();
        assertThatCode(() -> RegexSafetyCheck.assertSafe("^nagios$")).doesNotThrowAnyException();
    }

    @Test
    public void grouplessRepeatedDotStarAccepted_runtimeTimeoutIsTheControl() {
        // Characterisation, not endorsement. Both checks in this lint key on ')', so a pattern with
        // no group at all is never examined -- yet this one costs 5.7s at n=30 (21 chars, well under
        // MAX_PATTERN_LENGTH). The structural lint is therefore incomplete BY CONSTRUCTION and
        // cannot be made complete by adding more shapes.
        //
        // This is deliberate: the enforced control is the bounded, interruptible 50ms match in
        // BruteForceTracker.awaitMatchResult, which now COUNTS the login failure when it cannot
        // complete. This test exists so nobody re-promotes the lint to "the control".
        assertThatCode(() -> RegexSafetyCheck.assertSafe(".*.*.*.*.*.*.*.*.*.*x"))
                .doesNotThrowAnyException();
    }

    private static String repeat(String s, int n) {
        StringBuilder sb = new StringBuilder(s.length() * n);
        for (int i = 0; i < n; i++) {
            sb.append(s);
        }
        return sb.toString();
    }
}
