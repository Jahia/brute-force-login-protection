package org.jahia.community.bruteforceloginprotection.core;

import org.apache.commons.lang.StringUtils;
import org.jahia.community.bruteforceloginprotection.CidrMatcher;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedReader;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Periodically downloads the Tor exit-address list (default
 * {@code https://check.torproject.org/exit-addresses}) and holds it as a per-node in-memory set
 * of normalized IP strings for O(1) lookups on the auth-valve hot path.
 *
 * <p><b>Per-node by design</b> — the list is derived state re-fetchable from its external source,
 * so each cluster node fetches independently and nothing is stored in Hazelcast. As a consequence
 * Tor/static blocklist enforcement keeps working even while Hazelcast is down (unlike bans,
 * see ADR 0002).</p>
 *
 * <p><b>Failure semantics</b> (keep-last-known): any fetch failure — I/O error, non-200 status,
 * response-size cap, or a body with zero valid {@code ExitAddress} lines (truncated/garbage
 * responses must never wipe enforcement) — keeps the previously fetched list enforced and records
 * {@code lastError} for the admin UI. Retries happen on schedule indefinitely.</p>
 *
 * <p><b>SSRF note</b>: the URL is validated for scheme/userinfo only ({@code SettingsService});
 * private/internal hosts are deliberately allowed so operators can point at an internal mirror.
 * The URL is only settable with {@code bruteForceLoginProtectionAdmin}; the response is parsed
 * as strict IP literals and never echoed, so the residual SSRF surface is accepted.</p>
 */
@Component(immediate = true, service = TorExitNodeFetcher.class)
public class TorExitNodeFetcher {

    private static final Logger LOGGER = LoggerFactory.getLogger(TorExitNodeFetcher.class);

    private static final long TICK_SECONDS = 60L;
    private static final long INITIAL_DELAY_SECONDS = 10L;
    private static final int CONNECT_TIMEOUT_MS = 10_000;
    private static final int READ_TIMEOUT_MS = 30_000;
    // The real list is ~300 KB; anything near this cap is not the exit-address list.
    static final long MAX_RESPONSE_BYTES = 5L * 1024 * 1024;
    private static final String EXIT_ADDRESS_PREFIX = "ExitAddress ";

    /** Immutable snapshot of the fetcher state for status reporting (GraphQL / admin UI). */
    public record TorStatus(int entryCount, long lastSuccessMs, long lastAttemptMs, String lastError) {}

    @Reference
    private SettingsService settingsService;

    private final AtomicReference<Set<String>> exitAddresses = new AtomicReference<>(Collections.emptySet());
    private volatile long lastSuccessMs;
    private volatile long lastAttemptMs;
    private volatile String lastError;

    private ScheduledExecutorService executor;

    @Activate
    public void start() {
        executor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "bflp-tor-fetcher");
            t.setDaemon(true);
            return t;
        });
        // Fixed short tick that re-reads the current settings each pass: config changes
        // (enable/disable, interval, URL) take effect within one tick without any executor
        // rebuild, and there is no ordering dependency on GlobalConfigHolder at activation.
        executor.scheduleWithFixedDelay(this::tick, INITIAL_DELAY_SECONDS, TICK_SECONDS, TimeUnit.SECONDS);
    }

    @Deactivate
    public void stop() {
        if (executor != null) {
            executor.shutdownNow();
        }
    }

    // -----------------------------------------------------------------------------------------
    // Lookup + status (hot path / GraphQL)
    // -----------------------------------------------------------------------------------------

    /** True when {@code ip} is a currently known Tor exit address. Never does DNS. */
    public boolean isTorExit(String ip) {
        Set<String> current = exitAddresses.get();
        if (current.isEmpty()) {
            return false;
        }
        String normalized = normalizeIp(ip);
        return normalized != null && current.contains(normalized);
    }

    public TorStatus getStatus() {
        return new TorStatus(exitAddresses.get().size(), lastSuccessMs, lastAttemptMs, lastError);
    }

    /**
     * Synchronous fetch using the currently persisted settings, bypassing the schedule.
     * Backs the admin UI "Fetch now" button.
     */
    public IntegrationTestResult forceRefresh() {
        GlobalSettings settings = settingsService != null ? settingsService.getGlobalSettings() : null;
        if (settings == null || !settings.isTorBlocklistEnabled()) {
            return IntegrationTestResult.fail("Tor blocklist is not enabled");
        }
        fetchOnce(settings.getTorBlocklistUrl());
        String error = lastError;
        return error == null
                ? IntegrationTestResult.ok("Fetched " + exitAddresses.get().size() + " exit addresses")
                : IntegrationTestResult.fail(error);
    }

    // -----------------------------------------------------------------------------------------
    // Scheduled fetch
    // -----------------------------------------------------------------------------------------

    void tick() {
        // scheduleWithFixedDelay permanently cancels the task if a run lets ANY Throwable escape,
        // so the entire body is guarded — one bad pass must only skip one interval.
        try {
            GlobalSettings settings = settingsService != null ? settingsService.getGlobalSettings() : null;
            if (settings == null) {
                return;
            }
            if (isFetchDue(settings.isTorBlocklistEnabled(), System.currentTimeMillis(),
                    lastAttemptMs, settings.getTorBlocklistRefreshSeconds())) {
                fetchOnce(settings.getTorBlocklistUrl());
            }
        } catch (Throwable t) { // NOSONAR S1181: an escaping Throwable would silently kill the recurring task
            LOGGER.error("BFLP: Tor exit-list tick failed; will retry on next interval", t);
        }
    }

    /** Pure scheduling decision, extracted for tests. */
    static boolean isFetchDue(boolean enabled, long nowMs, long lastAttemptMs, long refreshSeconds) {
        if (!enabled) {
            return false;
        }
        return lastAttemptMs == 0L || nowMs - lastAttemptMs >= refreshSeconds * 1000L;
    }

    void fetchOnce(String url) {
        long now = System.currentTimeMillis();
        HttpURLConnection conn = null;
        try {
            // Re-validate before connecting: the .cfg on disk can be hand-edited past the
            // save-time validation in SettingsService.
            SettingsService.validateTorUrl(url);
            conn = (HttpURLConnection) URI.create(url).toURL().openConnection();
            conn.setInstanceFollowRedirects(false);
            conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
            conn.setReadTimeout(READ_TIMEOUT_MS);
            conn.setRequestProperty("User-Agent", "BFLP-TorBlocklist/1.0");
            int code = conn.getResponseCode();
            if (code != 200) {
                recordFailure("HTTP " + code, now);
                return;
            }
            Set<String> parsed;
            try (InputStream in = new CappedInputStream(conn.getInputStream(), MAX_RESPONSE_BYTES);
                 BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
                parsed = parseExitAddresses(reader);
            }
            if (parsed.isEmpty()) {
                // A truncated or garbage 200 response must never wipe enforcement.
                recordFailure("Response contained no valid ExitAddress entries", now);
                return;
            }
            recordSuccess(parsed, now);
            LOGGER.info("BFLP: Tor exit-address list refreshed: {} entries", parsed.size());
        } catch (Exception e) {
            recordFailure(summarize(e), now);
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    void recordSuccess(Set<String> addresses, long nowMs) {
        exitAddresses.set(Set.copyOf(addresses));
        lastSuccessMs = nowMs;
        lastAttemptMs = nowMs;
        lastError = null;
    }

    void recordFailure(String error, long nowMs) {
        lastAttemptMs = nowMs;
        lastError = error;
        LOGGER.warn("BFLP: Tor exit-address list fetch failed ({}); keeping last-known list of {} entries",
                error, exitAddresses.get().size());
    }

    private static String summarize(Exception e) {
        String msg = e.getMessage();
        return e.getClass().getSimpleName() + (StringUtils.isBlank(msg) ? "" : ": " + msg);
    }

    // -----------------------------------------------------------------------------------------
    // Parsing
    // -----------------------------------------------------------------------------------------

    /**
     * Parses the TorDNSEL export format: only {@code "ExitAddress <ip> <timestamp>"} lines carry
     * addresses; everything else ({@code ExitNode}, {@code Published}, {@code LastStatus}, …) is
     * ignored. Tokens are accepted only as strict IP literals (never resolved through DNS) and
     * normalized so v4-mapped v6 forms fold onto their IPv4 representation.
     */
    static Set<String> parseExitAddresses(BufferedReader reader) throws IOException {
        Set<String> out = new HashSet<>();
        String line;
        while ((line = reader.readLine()) != null) {
            if (!line.startsWith(EXIT_ADDRESS_PREFIX)) {
                continue;
            }
            String[] tokens = line.split(" ");
            if (tokens.length < 2) {
                continue;
            }
            String normalized = normalizeIp(tokens[1]);
            if (normalized != null) {
                out.add(normalized);
            }
        }
        return out;
    }

    /**
     * Returns the canonical textual form of a strict IP literal (e.g. folds {@code ::ffff:1.2.3.4}
     * to {@code 1.2.3.4}), or {@code null} when the value is not an IP literal. The
     * {@link CidrMatcher#isIpLiteral} guard runs first so {@code InetAddress.getByName} can never
     * trigger a DNS lookup on attacker-supplied content.
     */
    static String normalizeIp(String ip) {
        if (StringUtils.isBlank(ip) || !CidrMatcher.isIpLiteral(ip)) {
            return null;
        }
        try {
            return InetAddress.getByName(ip).getHostAddress();
        } catch (UnknownHostException e) {
            return null;
        }
    }

    /** Fails the read with an {@link IOException} once more than {@code maxBytes} were consumed. */
    static final class CappedInputStream extends FilterInputStream {
        private final long maxBytes;
        private long count;

        CappedInputStream(InputStream in, long maxBytes) {
            super(in);
            this.maxBytes = maxBytes;
        }

        @Override
        public int read() throws IOException {
            int b = super.read();
            if (b >= 0) {
                bump(1);
            }
            return b;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            int n = super.read(b, off, len);
            if (n > 0) {
                bump(n);
            }
            return n;
        }

        private void bump(int n) throws IOException {
            count += n;
            if (count > maxBytes) {
                throw new IOException("Response exceeds size cap of " + maxBytes + " bytes");
            }
        }
    }
}
