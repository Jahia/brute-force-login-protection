package org.jahia.community.bruteforceloginprotection;

import org.junit.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link CidrListCache}: CAS-cached parsing of comma-separated CIDR lists,
 * lenient skipping of malformed entries, and IPv4/IPv6 matching semantics.
 */
public class CidrListCacheTest {

    // -------------------------------------------------------------------------
    // matchesAny
    // -------------------------------------------------------------------------

    @Test
    public void matchesAny_ipv4InsideCidr_true() {
        CidrListCache cache = new CidrListCache();
        assertThat(cache.matchesAny("203.0.113.42", "203.0.113.0/24")).isTrue();
    }

    @Test
    public void matchesAny_ipv4OutsideCidr_false() {
        CidrListCache cache = new CidrListCache();
        assertThat(cache.matchesAny("198.51.100.1", "203.0.113.0/24")).isFalse();
    }

    @Test
    public void matchesAny_ipv6InsideCidr_true() {
        CidrListCache cache = new CidrListCache();
        assertThat(cache.matchesAny("2001:db8::1", "2001:db8::/32")).isTrue();
    }

    @Test
    public void matchesAny_multipleEntries_anyMatchWins() {
        CidrListCache cache = new CidrListCache();
        assertThat(cache.matchesAny("10.1.2.3", "203.0.113.0/24, 10.0.0.0/8")).isTrue();
    }

    @Test
    public void matchesAny_blankOrNullSource_false() {
        CidrListCache cache = new CidrListCache();
        assertThat(cache.matchesAny("203.0.113.42", null)).isFalse();
        assertThat(cache.matchesAny("203.0.113.42", "")).isFalse();
        assertThat(cache.matchesAny("203.0.113.42", "   ")).isFalse();
    }

    @Test
    public void matchesAny_invalidEntriesSkipped_validOnesStillMatch() {
        CidrListCache cache = new CidrListCache();
        assertThat(cache.matchesAny("10.1.2.3", "not-a-cidr, 10.0.0.0/8")).isTrue();
        assertThat(cache.matchesAny("203.0.113.42", "not-a-cidr")).isFalse();
    }

    // -------------------------------------------------------------------------
    // Caching semantics
    // -------------------------------------------------------------------------

    @Test
    public void matchers_sameSourceString_returnsSameCachedList() {
        CidrListCache cache = new CidrListCache();
        List<CidrMatcher> first = cache.matchers("10.0.0.0/8,192.168.0.0/16");
        List<CidrMatcher> second = cache.matchers("10.0.0.0/8,192.168.0.0/16");
        assertThat(second).isSameAs(first);
    }

    @Test
    public void matchers_changedSourceString_rebuilds() {
        CidrListCache cache = new CidrListCache();
        List<CidrMatcher> first = cache.matchers("10.0.0.0/8");
        List<CidrMatcher> second = cache.matchers("192.168.0.0/16");
        assertThat(second).isNotSameAs(first);
        assertThat(second).hasSize(1);
    }

    // -------------------------------------------------------------------------
    // validEntryCount
    // -------------------------------------------------------------------------

    @Test
    public void validEntryCount_countsOnlyParseableEntries() {
        CidrListCache cache = new CidrListCache();
        assertThat(cache.validEntryCount("10.0.0.0/8, garbage, 2001:db8::/32")).isEqualTo(2);
        assertThat(cache.validEntryCount("")).isZero();
        assertThat(cache.validEntryCount(null)).isZero();
    }
}
