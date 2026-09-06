package org.jahia.community.bruteforceloginprotection.core;

import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Best-effort lint that rejects regex patterns likely to enable catastrophic backtracking
 * (ReDoS). Intended for user-supplied {@code ignorePatterns} values stored in settings.
 *
 * <p><strong>This is not the control, and it cannot be made complete.</strong> Both checks key
 * on {@code ')'}, so a pattern with no group at all is never examined - yet
 * {@code .*.*.*.*.*.*.*.*.*.*x} costs about 5.7s at 30 characters, well inside
 * {@link #MAX_PATTERN_LENGTH}. Closing that by enumerating more shapes is not possible in a
 * character scanner.
 *
 * <p>The enforced control is the bounded, interruptible 50ms match in
 * {@code BruteForceTracker.awaitMatchResult}, which treats a pattern it cannot evaluate as NOT
 * matched and therefore still counts the login failure (GHSA-7qgr-2hqv-r344). This lint only
 * raises the bar at configuration time; it is applied on the GraphQL save path and again when a
 * hand-edited {@code .cfg} is loaded, where an offending entry is dropped rather than rejected.
 */
public final class RegexSafetyCheck {

    public static final int MAX_PATTERN_LENGTH = 200;
    public static final int MAX_QUANTIFIERS_PER_GROUP = 2;
    public static final int MAX_GROUP_DEPTH = 32;

    private RegexSafetyCheck() {
        // utility
    }

    /**
     * Validates {@code pattern}. On any safety violation, throws {@link IllegalArgumentException}
     * with a description suitable for surfacing to a GraphQL error.
     */
    public static void assertSafe(String pattern) {
        if (pattern == null) {
            return;
        }
        if (pattern.length() > MAX_PATTERN_LENGTH) {
            throw new IllegalArgumentException("Pattern exceeds " + MAX_PATTERN_LENGTH
                    + " chars: length=" + pattern.length());
        }
        try {
            Pattern.compile(pattern);
        } catch (PatternSyntaxException ex) {
            throw new IllegalArgumentException("Invalid regex: " + ex.getDescription(), ex);
        }
        assertNoNestedQuantifiers(pattern);
        assertGroupQuantifierDensity(pattern);
    }

    private static void assertNoNestedQuantifiers(String pattern) {
        // crude lint: a group close followed by *,+,? then another quantifier is a smell.
        // Skip positions where the group-close character is escaped (e.g. \)+ matches a
        // literal ')' followed by '+', which is perfectly safe and must not be rejected).
        boolean escaped = false;
        for (int i = 0; i < pattern.length() - 1; i++) {
            char c = pattern.charAt(i);
            boolean wasEscaped = escaped;
            escaped = !wasEscaped && c == '\\' && i + 1 < pattern.length();
            if (!wasEscaped && isNestedQuantifierAt(pattern, i)) {
                throw new IllegalArgumentException(
                        "Pattern contains nested quantifier at index " + i);
            }
        }
    }

    private static boolean isNestedQuantifierAt(String pattern, int i) {
        char c = pattern.charAt(i);
        if (c != ')' && c != '}') {
            return false;
        }
        char next = pattern.charAt(i + 1);
        if (next != '*' && next != '+' && next != '?' && next != '{') {
            return false;
        }
        // Group-close followed by a single quantifier is the classic (a+)+ ReDoS form.
        if (c == ')' && (next == '*' || next == '+' || next == '?')) {
            return true;
        }
        // Curly-quantifier on a group, or possessive/reluctant double-quantifier: require a
        // second quantifier character to be conservative and avoid false positives on }{.
        if (i + 2 >= pattern.length()) {
            return false;
        }
        char after = pattern.charAt(i + 2);
        return after == '*' || after == '+' || after == '?';
    }

    private static void assertGroupQuantifierDensity(String pattern) {
        GroupScan scan = new GroupScan();
        boolean escaped = false;
        for (int i = 0; i < pattern.length(); i++) {
            char c = pattern.charAt(i);
            boolean wasEscaped = escaped;
            escaped = !wasEscaped && c == '\\' && i + 1 < pattern.length();
            if (!wasEscaped && !escaped) {
                processGroupChar(pattern, i, scan);
            }
        }
    }

    /** Mutable state for the single forward pass in {@link #assertGroupQuantifierDensity}. */
    private static final class GroupScan {
        private final int[] quantsAtDepth = new int[MAX_GROUP_DEPTH + 1];
        // Counted separately because only UNBOUNDED quantifiers make a repeated group explode:
        // ([0-9]{2}){3} has a finite state space, (.*a){20} does not.
        private final int[] unboundedQuantsAtDepth = new int[MAX_GROUP_DEPTH + 1];
        private int depth;
    }

    /** Updates the scan state after processing one (non-escaped) character. */
    private static void processGroupChar(String pattern, int i, GroupScan scan) {
        char c = pattern.charAt(i);
        if (c == '(') {
            openGroup(scan);
            return;
        }
        if (c == ')' && scan.depth > 0) {
            closeGroup(pattern, i, scan);
            return;
        }
        if (scan.depth > 0 && (c == '+' || c == '*' || c == '{')) {
            scan.quantsAtDepth[scan.depth]++;
            if (c != '{') {
                scan.unboundedQuantsAtDepth[scan.depth]++;
            }
        }
    }

    private static void openGroup(GroupScan scan) {
        int next = scan.depth + 1;
        if (next > MAX_GROUP_DEPTH) {
            // Reject rather than silently stop tracking: extreme nesting is itself a ReDoS
            // smell, and letting it through would bypass the per-group quantifier check.
            throw new IllegalArgumentException("Pattern group nesting exceeds " + MAX_GROUP_DEPTH);
        }
        scan.quantsAtDepth[next] = 0;
        scan.unboundedQuantsAtDepth[next] = 0;
        scan.depth = next;
    }

    private static void closeGroup(String pattern, int closeIndex, GroupScan scan) {
        int depth = scan.depth;
        if (scan.quantsAtDepth[depth] > MAX_QUANTIFIERS_PER_GROUP) {
            throw new IllegalArgumentException("Pattern group has too many quantifiers ("
                    + scan.quantsAtDepth[depth] + " > " + MAX_QUANTIFIERS_PER_GROUP + ")");
        }
        // A bounded repetition applied to a group that itself contains an unbounded quantifier -
        // (.*a){20}, (a+){10} - is the shape that actually backtracks on Java's engine, where the
        // textbook (a+)+ forms caught above are optimised away and cost nothing. Checked here
        // rather than in isNestedQuantifierAt so the escape handling of this pass applies for free.
        if (scan.unboundedQuantsAtDepth[depth] > 0 && isFollowedByBoundedRepetition(pattern, closeIndex)) {
            throw new IllegalArgumentException(
                    "Pattern repeats a group containing an unbounded quantifier at index " + closeIndex);
        }
        scan.depth = depth - 1;
    }

    private static boolean isFollowedByBoundedRepetition(String pattern, int closeIndex) {
        return closeIndex + 1 < pattern.length() && pattern.charAt(closeIndex + 1) == '{';
    }
}
