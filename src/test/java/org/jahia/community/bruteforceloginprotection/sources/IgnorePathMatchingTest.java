package org.jahia.community.bruteforceloginprotection.sources;

import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link AuthValveFailureSource#matchesIgnoredPath}, the hot-path exemption that
 * stops non-login requests (e.g. a broken client polling a public content URL with a stale
 * {@code Authorization} header) from being counted as login failures.
 */
public class IgnorePathMatchingTest {

    // The concrete case that motivated the feature: Jahia's store module-list endpoint, reachable
    // both as a vanity URL and via /cms/render, hit with a wrong Authorization header.
    private static final String STORE_TOKEN = "modules-repository.moduleList.json";
    private static final List<String> STORE_IGNORE = Collections.singletonList(STORE_TOKEN);

    @Test
    public void matchesVanityStoreUrl() {
        assertThat(AuthValveFailureSource.matchesIgnoredPath(
                "/en/sites/store/contents/" + STORE_TOKEN, STORE_IGNORE)).isTrue();
    }

    @Test
    public void matchesInternalRenderStoreUrl() {
        // Same resource, different URI shape — substring matching covers both.
        assertThat(AuthValveFailureSource.matchesIgnoredPath(
                "/cms/render/live/en/sites/store/contents/" + STORE_TOKEN, STORE_IGNORE)).isTrue();
    }

    @Test
    public void doesNotMatchUnrelatedLoginPath() {
        assertThat(AuthValveFailureSource.matchesIgnoredPath("/cms/login", STORE_IGNORE)).isFalse();
    }

    @Test
    public void matchesAnyEntryInList() {
        List<String> entries = Arrays.asList("/health", STORE_TOKEN, "/metrics");
        assertThat(AuthValveFailureSource.matchesIgnoredPath("/actuator/metrics", entries)).isTrue();
    }

    @Test
    public void matchingIsCaseSensitive() {
        assertThat(AuthValveFailureSource.matchesIgnoredPath(
                "/EN/SITES/STORE/CONTENTS/" + STORE_TOKEN.toUpperCase(), STORE_IGNORE)).isFalse();
    }

    @Test
    public void nullRequestUriIsNotMatched() {
        assertThat(AuthValveFailureSource.matchesIgnoredPath(null, STORE_IGNORE)).isFalse();
    }

    @Test
    public void nullOrEmptyIgnoreListIsNotMatched() {
        assertThat(AuthValveFailureSource.matchesIgnoredPath("/anything", null)).isFalse();
        assertThat(AuthValveFailureSource.matchesIgnoredPath("/anything", Collections.emptyList())).isFalse();
    }

    @Test
    public void blankAndNullEntriesNeverMatch() {
        // An empty entry would substring-match every URI; it must be treated as "no rule".
        assertThat(AuthValveFailureSource.matchesIgnoredPath("/anything", Arrays.asList("", null)))
                .isFalse();
    }
}
