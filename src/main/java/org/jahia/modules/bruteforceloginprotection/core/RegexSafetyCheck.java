package org.jahia.modules.bruteforceloginprotection.core;

import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Lightweight lint that rejects regex patterns likely to enable catastrophic backtracking
 * (ReDoS). Intended for user-supplied {@code ignorePatterns} values stored in settings.
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
        int depth = 0;
        int[] quantsAtDepth = new int[MAX_GROUP_DEPTH + 1];
        boolean escaped = false;
        for (int i = 0; i < pattern.length(); i++) {
            char c = pattern.charAt(i);
            boolean wasEscaped = escaped;
            escaped = !wasEscaped && c == '\\' && i + 1 < pattern.length();
            if (!wasEscaped && !escaped) {
                depth = processGroupChar(c, depth, quantsAtDepth);
            }
        }
    }

    /** Updates and returns the new nesting depth after processing one (non-escaped) character. */
    private static int processGroupChar(char c, int depth, int[] quantsAtDepth) {
        if (c == '(') {
            return openGroup(depth, quantsAtDepth);
        }
        if (c == ')' && depth > 0) {
            return closeGroup(depth, quantsAtDepth);
        }
        if ((c == '+' || c == '*' || c == '{') && depth > 0) {
            quantsAtDepth[depth]++;
        }
        return depth;
    }

    private static int openGroup(int depth, int[] quantsAtDepth) {
        int next = depth + 1;
        if (next > MAX_GROUP_DEPTH) {
            // Reject rather than silently stop tracking: extreme nesting is itself a ReDoS
            // smell, and letting it through would bypass the per-group quantifier check.
            throw new IllegalArgumentException("Pattern group nesting exceeds " + MAX_GROUP_DEPTH);
        }
        quantsAtDepth[next] = 0;
        return next;
    }

    private static int closeGroup(int depth, int[] quantsAtDepth) {
        if (quantsAtDepth[depth] > MAX_QUANTIFIERS_PER_GROUP) {
            throw new IllegalArgumentException("Pattern group has too many quantifiers ("
                    + quantsAtDepth[depth] + " > " + MAX_QUANTIFIERS_PER_GROUP + ")");
        }
        return depth - 1;
    }
}
