package org.jahia.community.bruteforceloginprotection.core;

import com.sun.net.httpserver.HttpServer;
import org.junit.After;
import org.junit.Test;

import java.lang.reflect.Field;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * U10 — response-size and redirect hardening on the Tor exit-list fetch, exercised against a
 * REAL local {@link HttpServer} (not a mock/spy) so the redirect-disabled behavior is proven
 * end-to-end rather than simulated. Also D4 — repeated sequential {@code forceRefresh()} calls
 * are unthrottled (only concurrent overlap is guarded by the single-flight flag).
 *
 * <p>Uses {@code http://127.0.0.1:.../} URLs, which {@code SettingsService.validateTorUrl}
 * deliberately allows (D3's asymmetry with the webhook SSRF guard) -- this is what makes a real
 * local server usable here at all.</p>
 */
public class TorExitNodeFetcherHardeningTest {

    private HttpServer server;

    @After
    public void tearDown() {
        if (server != null) {
            server.stop(0);
        }
    }

    private static void inject(Object target, String field, Object value) throws Exception {
        Field f = target.getClass().getDeclaredField(field);
        f.setAccessible(true);
        f.set(target, value);
    }

    private String startServerRedirecting() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/exit-addresses", exchange -> {
            exchange.getResponseHeaders().add("Location", "http://127.0.0.1:1/elsewhere");
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        });
        server.start();
        return "http://127.0.0.1:" + server.getAddress().getPort() + "/exit-addresses";
    }

    private String startServerServingExitList(AtomicInteger hitCount) throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        byte[] body = ("ExitAddress 1.2.3.4 1700000000\n").getBytes(StandardCharsets.UTF_8);
        server.createContext("/exit-addresses", exchange -> {
            hitCount.incrementAndGet();
            exchange.sendResponseHeaders(200, body.length);
            try (var os = exchange.getResponseBody()) {
                os.write(body);
            }
        });
        server.start();
        return "http://127.0.0.1:" + server.getAddress().getPort() + "/exit-addresses";
    }

    private TorExitNodeFetcher newFetcherWithSettings(String url, long refreshSeconds) throws Exception {
        TorExitNodeFetcher fetcher = new TorExitNodeFetcher();
        SettingsService settingsService = mock(SettingsService.class);
        when(settingsService.getGlobalSettings()).thenReturn(GlobalSettings.builder()
                .torBlocklistEnabled(true)
                .torBlocklistUrl(url)
                .torBlocklistRefreshSeconds(refreshSeconds)
                .build());
        inject(fetcher, "settingsService", settingsService);
        return fetcher;
    }

    // -------------------------------------------------------------------------------------------
    // U10 — redirects are NOT followed
    // -------------------------------------------------------------------------------------------

    @Test
    public void redirectIsNotFollowed_recordsHttp302RatherThanFollowing() throws Exception {
        String url = startServerRedirecting();
        TorExitNodeFetcher fetcher = newFetcherWithSettings(url, 3600L);

        boolean ran = fetcher.fetchOnce(url);

        assertThat(ran).isTrue();
        TorExitNodeFetcher.TorStatus status = fetcher.getStatus();
        assertThat(status.lastError()).isEqualTo("HTTP 302");
        assertThat(status.entryCount()).isZero();
    }

    // -------------------------------------------------------------------------------------------
    // U10 — connect/read timeouts applied (asserted via the now package-private constants, to
    // avoid a slow/flaky real-time timeout race against a live 10s/30s timer).
    // -------------------------------------------------------------------------------------------

    @Test
    public void connectAndReadTimeoutsAreTenAndThirtySeconds() {
        assertThat(TorExitNodeFetcher.CONNECT_TIMEOUT_MS).isEqualTo(10_000);
        assertThat(TorExitNodeFetcher.READ_TIMEOUT_MS).isEqualTo(30_000);
    }

    // -------------------------------------------------------------------------------------------
    // D4 — forceRefresh() called twice sequentially: both succeed and both actually re-fetch;
    // only the single-flight guard prevents CONCURRENT overlap, not sequential repetition.
    // -------------------------------------------------------------------------------------------

    @Test
    public void forceRefreshCalledTwiceSequentially_bothSucceedAndBothHitTheServer() throws Exception {
        AtomicInteger hits = new AtomicInteger(0);
        String url = startServerServingExitList(hits);
        TorExitNodeFetcher fetcher = newFetcherWithSettings(url, 3600L);

        IntegrationTestResult first = fetcher.forceRefresh();
        IntegrationTestResult second = fetcher.forceRefresh();

        assertThat(first.success()).isTrue();
        assertThat(second.success()).isTrue();
        assertThat(hits.get()).isEqualTo(2);
    }
}
