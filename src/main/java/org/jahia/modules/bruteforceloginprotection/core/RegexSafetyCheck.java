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
        for (int i = 0; i < pattern.length() - 1; i++) {
            char c = pattern.charAt(i);
            if (c != ')' && c != '}') {
                continue;
            }
            char next = pattern.charAt(i + 1);
            if (next != '*' && next != '+' && next != '?' && next != '{') {
                continue;
            }
            if (i + 2 < pattern.length()) {
                char after = pattern.charAt(i + 2);
                if (after == '*' || after == '+' || after == '?') {
                    throw new IllegalArgumentException(
                            "Pattern contains nested quantifier at index " + i);
                }
            }
        }
    }

    private static void assertGroupQuantifierDensity(String pattern) {
        int depth = 0;
        int[] quantsAtDepth = new int[64];
        for (int i = 0; i < pattern.length(); i++) {
            char c = pattern.charAt(i);
            if (c == '\\' && i + 1 < pattern.length()) {
                // skip escaped char
                i++;
                continue;
            }
            if (c == '(' && depth + 1 < quantsAtDepth.length) {
                depth++;
                quantsAtDepth[depth] = 0;
            } else if (c == ')' && depth > 0) {
                if (quantsAtDepth[depth] > MAX_QUANTIFIERS_PER_GROUP) {
                    throw new IllegalArgumentException("Pattern group has too many quantifiers ("
                            + quantsAtDepth[depth] + " > " + MAX_QUANTIFIERS_PER_GROUP + ")");
                }
                depth--;
            } else if ((c == '+' || c == '*' || c == '{') && depth > 0) {
                quantsAtDepth[depth]++;
            }
        }
    }
}
