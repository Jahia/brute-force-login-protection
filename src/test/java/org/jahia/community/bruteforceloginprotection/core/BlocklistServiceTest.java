package org.jahia.community.bruteforceloginprotection.core;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.Collections;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link BlocklistService}: block-decision precedence
 * (activated → whitelist wins → static blocklist → Tor list) and the per-IP audit throttle.
 */
@RunWith(MockitoJUnitRunner.class)
public class BlocklistServiceTest {

    @Mock
    private SettingsService settingsService;

    @Mock
    private AuditLogger auditLogger;

    private TorExitNodeFetcher torFetcher;
    private BlocklistService service;
    private final AtomicLong clock = new AtomicLong(1_000_000L);

    @Before
    public void setUp() {
        torFetcher = new TorExitNodeFetcher();
        service = new BlocklistService(settingsService, torFetcher, auditLogger, clock::get);
    }

    private void settings(boolean activated, String whitelist, String blocklist, boolean torEnabled) {
        GlobalSettings s = GlobalSettings.builder()
                .activated(activated)
                .whitelistIps(whitelist)
                .ignorePatterns(Collections.emptyList())
                .blocklistIps(blocklist)
                .torBlocklistEnabled(torEnabled)
                .torBlocklistUrl("https://check.torproject.org/exit-addresses")
                .torBlocklistRefreshSeconds(3600L)
                .auditLogMaxEntries(1000)
                .recidiveFactor(2.0)
                .maxBanTimeSec(86400L)
                .build();
        lenient().when(settingsService.getGlobalSettings()).thenReturn(s);
    }

    // -------------------------------------------------------------------------
    // getBlockReason precedence
    // -------------------------------------------------------------------------

    @Test
    public void deactivated_neverBlocks() {
        settings(false, "", "0.0.0.0/0", true);
        torFetcher.recordSuccess(Set.of("1.2.3.4"), clock.get());
        assertThat(service.getBlockReason("1.2.3.4")).isNull();
    }

    @Test
    public void staticBlocklistMatch_returnsStaticReason() {
        settings(true, "", "203.0.113.0/24", false);
        assertThat(service.getBlockReason("203.0.113.42")).isEqualTo(BlocklistService.REASON_STATIC);
    }

    @Test
    public void noMatch_returnsNull() {
        settings(true, "", "203.0.113.0/24", false);
        assertThat(service.getBlockReason("198.51.100.1")).isNull();
    }

    @Test
    public void torExitMatch_returnsTorReason_onlyWhenEnabled() {
        settings(true, "", "", true);
        torFetcher.recordSuccess(Set.of("185.220.101.32"), clock.get());
        assertThat(service.getBlockReason("185.220.101.32")).isEqualTo(BlocklistService.REASON_TOR);

        settings(true, "", "", false);
        assertThat(service.getBlockReason("185.220.101.32")).isNull();
    }

    @Test
    public void whitelistBeatsStaticBlocklist() {
        settings(true, "203.0.113.42/32", "203.0.113.0/24", false);
        assertThat(service.getBlockReason("203.0.113.42")).isNull();
        // Other addresses of the blocklisted range are still blocked
        assertThat(service.getBlockReason("203.0.113.43")).isEqualTo(BlocklistService.REASON_STATIC);
    }

    @Test
    public void whitelistBeatsTorList() {
        settings(true, "185.220.101.0/24", "", true);
        torFetcher.recordSuccess(Set.of("185.220.101.32"), clock.get());
        assertThat(service.getBlockReason("185.220.101.32")).isNull();
    }

    @Test
    public void staticBlocklistWinsOverTor_whenBothMatch() {
        settings(true, "", "185.220.101.0/24", true);
        torFetcher.recordSuccess(Set.of("185.220.101.32"), clock.get());
        assertThat(service.getBlockReason("185.220.101.32")).isEqualTo(BlocklistService.REASON_STATIC);
    }

    @Test
    public void blankIp_neverBlocks() {
        settings(true, "", "0.0.0.0/0", false);
        assertThat(service.getBlockReason(null)).isNull();
        assertThat(service.getBlockReason("")).isNull();
    }

    // -------------------------------------------------------------------------
    // onBlocked audit throttle (1 audit entry per IP per hour)
    // -------------------------------------------------------------------------

    @Test
    public void onBlocked_firstHit_writesAuditEntry() {
        settings(true, "", "203.0.113.0/24", false);
        service.onBlocked("203.0.113.42", BlocklistService.REASON_STATIC);
        verify(auditLogger).log(eq(AuditLogger.EVENT_BLOCKED), eq("203.0.113.42"), isNull(),
                eq(BlocklistService.REASON_STATIC), anyString());
    }

    @Test
    public void onBlocked_secondHitWithinHour_throttled() {
        settings(true, "", "203.0.113.0/24", false);
        service.onBlocked("203.0.113.42", BlocklistService.REASON_STATIC);
        clock.addAndGet(30 * 60 * 1000L); // +30 min
        service.onBlocked("203.0.113.42", BlocklistService.REASON_STATIC);
        verify(auditLogger, times(1)).log(any(), any(), any(), any(), any());
    }

    @Test
    public void onBlocked_hitAfterAnHour_auditedAgain() {
        settings(true, "", "203.0.113.0/24", false);
        service.onBlocked("203.0.113.42", BlocklistService.REASON_STATIC);
        clock.addAndGet(61 * 60 * 1000L); // +61 min
        service.onBlocked("203.0.113.42", BlocklistService.REASON_STATIC);
        verify(auditLogger, times(2)).log(any(), any(), any(), any(), any());
    }

    @Test
    public void onBlocked_differentIps_auditedIndependently() {
        settings(true, "", "203.0.113.0/24", false);
        service.onBlocked("203.0.113.42", BlocklistService.REASON_STATIC);
        service.onBlocked("203.0.113.43", BlocklistService.REASON_STATIC);
        verify(auditLogger, times(2)).log(any(), any(), any(), any(), any());
    }

    @Test
    public void throttleMap_prunedWhenOverBound() {
        settings(true, "", "0.0.0.0/0", false);
        // Fill beyond the prune threshold with entries, then age them out
        for (int i = 0; i < 10_001; i++) {
            service.onBlocked("10.0." + (i / 256) + "." + (i % 256), BlocklistService.REASON_STATIC);
        }
        clock.addAndGet(3 * 60 * 60 * 1000L); // +3h — all entries now stale
        service.onBlocked("192.0.2.1", BlocklistService.REASON_STATIC);
        assertThat(service.throttleMapSize()).isLessThan(10_000);
    }

    @Test
    public void throttleMap_hardCapBoundsFreshChurn() {
        settings(true, "", "0.0.0.0/0", false);
        // Continuous churn of DISTINCT fresh IPs (the realistic rotation attack): nothing is
        // stale, so pruning cannot help — the hard cap must bound the map instead.
        for (int i = 0; i < BlocklistService.THROTTLE_HARD_CAP + 500; i++) {
            service.onBlocked("10." + (i / 65_536) + "." + ((i / 256) % 256) + "." + (i % 256),
                    BlocklistService.REASON_STATIC);
            clock.addAndGet(1L); // keep every entry fresh
        }
        assertThat(service.throttleMapSize()).isLessThanOrEqualTo(BlocklistService.THROTTLE_HARD_CAP);
        // Past the cap, audits are skipped for new IPs but only HARD_CAP entries were logged
        verify(auditLogger, times(BlocklistService.THROTTLE_HARD_CAP)).log(any(), any(), any(), any(), any());
    }

    @Test
    public void onBlocked_neverThrows_whenAuditLoggerFails() {
        settings(true, "", "203.0.113.0/24", false);
        org.mockito.Mockito.doThrow(new RuntimeException("JCR down"))
                .when(auditLogger).log(any(), any(), any(), any(), any());
        // Must not propagate — blocking the request matters more than auditing it
        service.onBlocked("203.0.113.42", BlocklistService.REASON_STATIC);
    }

    // -------------------------------------------------------------------------
    // Status helper
    // -------------------------------------------------------------------------

    @Test
    public void staticEntryCount_countsValidEntries() {
        settings(true, "", "203.0.113.0/24, garbage, 2001:db8::/32", false);
        assertThat(service.getStaticEntryCount()).isEqualTo(2);
    }

    @Test
    public void staticEntryCount_blankList_zero() {
        settings(true, "", "", false);
        assertThat(service.getStaticEntryCount()).isZero();
        verify(auditLogger, never()).log(any(), any(), any(), any(), any());
    }
}
