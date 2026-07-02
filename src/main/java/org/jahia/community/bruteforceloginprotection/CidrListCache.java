package org.jahia.community.bruteforceloginprotection;

import org.apache.commons.lang.StringUtils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/**
 * CAS-cached parser for a comma-separated CIDR list. The parsed {@link CidrMatcher} list is
 * rebuilt only when the source string changes, so per-request callers (auth valve hot path)
 * never re-parse an unchanged list. Malformed entries are silently skipped at match time —
 * strict validation, where wanted, belongs at save time (see {@code SettingsService}).
 *
 * <p>Thread-safe; instances are cheap and intended to be one-per-consumer fields.</p>
 */
public final class CidrListCache {

    private record Cache(String source, List<CidrMatcher> matchers) {}

    private final AtomicReference<Cache> cache = new AtomicReference<>(new Cache(null, Collections.emptyList()));

    /**
     * Returns the parsed {@link CidrMatcher} list for the given comma-separated string,
     * rebuilding and caching it only when the string has changed.
     */
    public List<CidrMatcher> matchers(String commaSeparated) {
        if (StringUtils.isBlank(commaSeparated)) {
            return Collections.emptyList();
        }
        Cache current = cache.get();
        if (commaSeparated.equals(current.source())) {
            return current.matchers();
        }
        List<CidrMatcher> matchers = new ArrayList<>();
        for (String entry : commaSeparated.split(",")) {
            String trimmed = StringUtils.trimToNull(entry);
            if (trimmed == null) {
                continue;
            }
            try {
                matchers.add(new CidrMatcher(trimmed));
            } catch (IllegalArgumentException ignored) {
                // skip invalid CIDR — lenient at match time by design
            }
        }
        List<CidrMatcher> immutable = Collections.unmodifiableList(matchers);
        cache.compareAndSet(current, new Cache(commaSeparated, immutable));
        return immutable;
    }

    /** True when {@code ip} matches at least one valid entry of the list. Blank list ⇒ false. */
    public boolean matchesAny(String ip, String commaSeparated) {
        for (CidrMatcher matcher : matchers(commaSeparated)) {
            if (matcher.matches(ip)) {
                return true;
            }
        }
        return false;
    }

    /** Number of entries that parse as valid CIDR/IP notation (for status reporting). */
    public int validEntryCount(String commaSeparated) {
        return matchers(commaSeparated).size();
    }
}
