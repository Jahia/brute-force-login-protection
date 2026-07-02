package org.jahia.community.bruteforceloginprotection.core;

import org.junit.Test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link TorExitNodeFetcher}: exit-address parsing, refresh scheduling
 * decisions, IP normalization, and keep-last-known-list failure semantics.
 * No network, no OSGi container.
 */
public class TorExitNodeFetcherTest {

    private static final String SAMPLE_BODY = ""
            + "ExitNode 0011BD2485AD45D984EC4159C88FC066E5E3300E\n"
            + "Published 2026-07-01 19:47:53\n"
            + "LastStatus 2026-07-02 04:00:00\n"
            + "ExitAddress 162.247.72.201 2026-07-02 04:20:11\n"
            + "ExitNode 0098C475875ABC4AA864738B1D1079F711C38287\n"
            + "Published 2026-07-01 13:52:03\n"
            + "LastStatus 2026-07-01 23:00:00\n"
            + "ExitAddress 185.220.101.32 2026-07-01 23:23:11\n"
            + "ExitAddress 185.220.101.33 2026-07-01 23:23:12\n";

    private static BufferedReader reader(String s) {
        return new BufferedReader(new StringReader(s));
    }

    // -------------------------------------------------------------------------
    // parseExitAddresses
    // -------------------------------------------------------------------------

    @Test
    public void parse_nominalBody_collectsAllExitAddresses() throws IOException {
        Set<String> ips = TorExitNodeFetcher.parseExitAddresses(reader(SAMPLE_BODY));
        assertThat(ips).containsExactlyInAnyOrder("162.247.72.201", "185.220.101.32", "185.220.101.33");
    }

    @Test
    public void parse_ignoresNonExitAddressLines() throws IOException {
        Set<String> ips = TorExitNodeFetcher.parseExitAddresses(
                reader("ExitNode ABC\nPublished 2026-01-01\nGarbageLine 1.2.3.4\n"));
        assertThat(ips).isEmpty();
    }

    @Test
    public void parse_rejectsHostnameTokens() throws IOException {
        Set<String> ips = TorExitNodeFetcher.parseExitAddresses(
                reader("ExitAddress evil.example.com 2026-07-02 04:20:11\n"));
        assertThat(ips).isEmpty();
    }

    @Test
    public void parse_rejectsOutOfRangeIp() throws IOException {
        Set<String> ips = TorExitNodeFetcher.parseExitAddresses(
                reader("ExitAddress 999.1.1.1 2026-07-02 04:20:11\n"));
        assertThat(ips).isEmpty();
    }

    @Test
    public void parse_normalizesV4MappedV6() throws IOException {
        Set<String> ips = TorExitNodeFetcher.parseExitAddresses(
                reader("ExitAddress ::ffff:1.2.3.4 2026-07-02 04:20:11\n"));
        assertThat(ips).containsExactly("1.2.3.4");
    }

    @Test
    public void parse_missingIpToken_skipped() throws IOException {
        Set<String> ips = TorExitNodeFetcher.parseExitAddresses(reader("ExitAddress\nExitAddress \n"));
        assertThat(ips).isEmpty();
    }

    // -------------------------------------------------------------------------
    // Byte cap
    // -------------------------------------------------------------------------

    @Test
    public void cappedStream_exceedingCap_throws() {
        byte[] data = new byte[2048];
        assertThatThrownBy(() -> {
            try (java.io.InputStream in = new TorExitNodeFetcher.CappedInputStream(
                    new java.io.ByteArrayInputStream(data), 1024)) {
                in.readAllBytes();
            }
        }).isInstanceOf(IOException.class).hasMessageContaining("size cap");
    }

    @Test
    public void cappedStream_underCap_readsFully() throws IOException {
        byte[] data = new byte[512];
        try (java.io.InputStream in = new TorExitNodeFetcher.CappedInputStream(
                new java.io.ByteArrayInputStream(data), 1024)) {
            assertThat(in.readAllBytes()).hasSize(512);
        }
    }

    // -------------------------------------------------------------------------
    // isFetchDue
    // -------------------------------------------------------------------------

    @Test
    public void isFetchDue_disabled_neverDue() {
        assertThat(TorExitNodeFetcher.isFetchDue(false, 1_000_000L, 0L, 300L)).isFalse();
    }

    @Test
    public void isFetchDue_neverAttempted_due() {
        assertThat(TorExitNodeFetcher.isFetchDue(true, 1_000_000L, 0L, 300L)).isTrue();
    }

    @Test
    public void isFetchDue_intervalElapsed_due() {
        long now = 1_000_000L;
        assertThat(TorExitNodeFetcher.isFetchDue(true, now, now - 301_000L, 300L)).isTrue();
    }

    @Test
    public void isFetchDue_intervalNotElapsed_notDue() {
        long now = 1_000_000L;
        assertThat(TorExitNodeFetcher.isFetchDue(true, now, now - 100_000L, 300L)).isFalse();
    }

    // -------------------------------------------------------------------------
    // isTorExit + normalization symmetry
    // -------------------------------------------------------------------------

    @Test
    public void isTorExit_normalizesLookupSide() {
        TorExitNodeFetcher fetcher = new TorExitNodeFetcher();
        fetcher.recordSuccess(Set.of("1.2.3.4"), 1_000L);
        assertThat(fetcher.isTorExit("1.2.3.4")).isTrue();
        assertThat(fetcher.isTorExit("::ffff:1.2.3.4")).isTrue();
        assertThat(fetcher.isTorExit("5.6.7.8")).isFalse();
        assertThat(fetcher.isTorExit("not-an-ip")).isFalse();
        assertThat(fetcher.isTorExit(null)).isFalse();
    }

    @Test
    public void isTorExit_emptyList_false() {
        TorExitNodeFetcher fetcher = new TorExitNodeFetcher();
        assertThat(fetcher.isTorExit("1.2.3.4")).isFalse();
    }

    // -------------------------------------------------------------------------
    // Keep-last-known-list failure semantics + status
    // -------------------------------------------------------------------------

    @Test
    public void recordFailure_keepsPreviousListAndExposesError() {
        TorExitNodeFetcher fetcher = new TorExitNodeFetcher();
        fetcher.recordSuccess(Set.of("1.2.3.4", "5.6.7.8"), 1_000L);
        fetcher.recordFailure("HTTP 503", 2_000L);

        assertThat(fetcher.isTorExit("1.2.3.4")).isTrue();
        TorExitNodeFetcher.TorStatus status = fetcher.getStatus();
        assertThat(status.entryCount()).isEqualTo(2);
        assertThat(status.lastSuccessMs()).isEqualTo(1_000L);
        assertThat(status.lastAttemptMs()).isEqualTo(2_000L);
        assertThat(status.lastError()).isEqualTo("HTTP 503");
    }

    @Test
    public void recordSuccess_clearsLastError() {
        TorExitNodeFetcher fetcher = new TorExitNodeFetcher();
        fetcher.recordFailure("HTTP 503", 1_000L);
        fetcher.recordSuccess(Set.of("1.2.3.4"), 2_000L);

        TorExitNodeFetcher.TorStatus status = fetcher.getStatus();
        assertThat(status.lastError()).isNull();
        assertThat(status.lastSuccessMs()).isEqualTo(2_000L);
        assertThat(status.entryCount()).isEqualTo(1);
    }

    @Test
    public void statusBeforeAnyAttempt_zeroesAndNoError() {
        TorExitNodeFetcher.TorStatus status = new TorExitNodeFetcher().getStatus();
        assertThat(status.entryCount()).isZero();
        assertThat(status.lastSuccessMs()).isZero();
        assertThat(status.lastAttemptMs()).isZero();
        assertThat(status.lastError()).isNull();
    }
}
