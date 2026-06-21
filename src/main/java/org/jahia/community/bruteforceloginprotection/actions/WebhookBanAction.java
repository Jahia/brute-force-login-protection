package org.jahia.community.bruteforceloginprotection.actions;

import org.apache.commons.lang.StringUtils;
import org.jahia.community.bruteforceloginprotection.core.BanContext;
import org.jahia.community.bruteforceloginprotection.core.GlobalSettings;
import org.jahia.community.bruteforceloginprotection.core.IntegrationTestResult;
import org.jahia.community.bruteforceloginprotection.core.SettingsService;
import org.jahia.community.bruteforceloginprotection.spi.BanAction;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

@Component(immediate = true, service = {BanAction.class, WebhookBanAction.class})
public class WebhookBanAction implements BanAction {

    private static final Logger LOGGER = LoggerFactory.getLogger(WebhookBanAction.class);
    private static final long OVERALL_DEADLINE_SEC = 10L;
    private static final int EXECUTOR_POOL_SIZE = 2;
    private static final long SHUTDOWN_AWAIT_SEC = 5L;
    private final AtomicInteger webhookThreadCounter = new AtomicInteger();

    // Created in @Activate and shut down in @Deactivate so a bundle refresh never leaves
    // submissions hitting a terminated pool.
    private ExecutorService webhookExecutor;

    @Reference
    private SettingsService settingsService;

    @Activate
    protected void activate() {
        webhookExecutor = Executors.newFixedThreadPool(EXECUTOR_POOL_SIZE, r -> {
            Thread t = new Thread(r, "bflp-webhook-" + webhookThreadCounter.incrementAndGet());
            t.setDaemon(true);
            return t;
        });
    }

    @Deactivate
    protected void deactivate() {
        if (webhookExecutor == null) {
            return;
        }
        webhookExecutor.shutdown();
        try {
            if (!webhookExecutor.awaitTermination(SHUTDOWN_AWAIT_SEC, TimeUnit.SECONDS)) {
                webhookExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            webhookExecutor.shutdownNow();
        }
    }

    @Override
    public String getName() {
        return "webhook";
    }

    @Override
    public int priority() {
        return 20;
    }

    @Override
    public void onBan(BanContext context) {
        post(context, "ban");
    }

    @Override
    public void onUnban(BanContext context) {
        post(context, "unban");
    }

    private void post(BanContext context, String event) {
        GlobalSettings settings = settingsService.getGlobalSettings();
        String url = settings.getWebhookUrl();
        if (StringUtils.isBlank(url)) {
            return;
        }
        final InetAddress pinned;
        try {
            pinned = WebhookUrlValidator.validateAndResolve(url);
        } catch (IllegalArgumentException ex) {
            LOGGER.warn("BFLP: webhook URL rejected by SSRF guard: {}", ex.getMessage());
            return;
        }
        String body = buildJson(context, event);
        String secret = settings.getWebhookSecret();
        // After @Deactivate the executor is null/shut down; submitting would throw. Skip quietly so
        // a ban firing during a bundle refresh doesn't surface a spurious error.
        if (webhookExecutor == null) {
            return;
        }
        final AtomicReference<HttpURLConnection> connHolder = new AtomicReference<>();
        Future<Void> future = webhookExecutor.submit(() -> {
            deliver(url, pinned, body, secret, connHolder);
            return null;
        });
        try {
            future.get(OVERALL_DEADLINE_SEC, TimeUnit.SECONDS);
        } catch (TimeoutException te) {
            future.cancel(true);
            HttpURLConnection conn = connHolder.get();
            if (conn != null) {
                try { conn.disconnect(); } catch (Exception ignored) { /* best-effort */ }
            }
            LOGGER.warn("BFLP: webhook overall deadline exceeded ({}s), aborting", OVERALL_DEADLINE_SEC);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            future.cancel(true);
        } catch (Exception ex) {
            LOGGER.debug("BFLP: webhook task failed: {}", ex.getMessage());
        }
    }

    /**
     * Sends a synchronous test payload to the configured webhook URL using the currently
     * persisted settings, applying the same SSRF guard + HMAC signing as the production path.
     * Intended for the admin UI "Send test webhook" button.
     */
    public IntegrationTestResult sendTest() {
        GlobalSettings settings = settingsService.getGlobalSettings();
        String url = settings.getWebhookUrl();
        if (StringUtils.isBlank(url)) {
            return IntegrationTestResult.fail("No webhook URL configured");
        }
        final InetAddress pinned;
        try {
            pinned = WebhookUrlValidator.validateAndResolve(url);
        } catch (IllegalArgumentException ex) {
            return IntegrationTestResult.fail("URL rejected: " + ex.getMessage());
        }
        // Slack-compatible: include a top-level "text" field. Other consumers can keep using
        // the structured fields; Slack rejects payloads without "text" with HTTP 400.
        String body = "{\"event\":\"test\","
                + "\"text\":\"BFLP test webhook\","
                + "\"message\":\"BFLP test webhook\","
                + "\"timestamp\":" + System.currentTimeMillis() + "}";
        String secret = settings.getWebhookSecret();
        HttpURLConnection conn = null;
        try {
            conn = openConnection(url, pinned);
            int code = sendPost(conn, body, secret);
            String summary = "HTTP " + code;
            // Redirects are disabled, so treat any non-2xx (including 3xx) as a failure.
            return code < 300
                    ? IntegrationTestResult.ok("Webhook accepted (" + summary + ")")
                    : IntegrationTestResult.fail("Webhook rejected (" + summary + ")");
        } catch (Exception e) {
            return IntegrationTestResult.fail("Delivery failed: " + e.getMessage());
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    private static void deliver(String url, InetAddress pinned, String body, String secret, AtomicReference<HttpURLConnection> connHolder) {
        try {
            HttpURLConnection conn = openConnection(url, pinned);
            connHolder.set(conn);
            int code = sendPost(conn, body, secret);
            if (code >= 300) {
                LOGGER.warn("BFLP: webhook returned status {}", code);
            }
            conn.disconnect();
        } catch (Exception e) {
            LOGGER.warn("BFLP: webhook delivery failed: {}", e.getMessage());
        }
    }

    /**
     * Configures the (already-opened) connection as a signed JSON POST, writes the body, and
     * returns the HTTP status code. Shared by the production delivery and the admin test path so
     * both apply identical headers, timeouts, and HMAC signing.
     */
    private static int sendPost(HttpURLConnection conn, String body, String secret) throws java.io.IOException {
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setRequestProperty("User-Agent", "BFLP-Webhook/1.0");
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(5000);
        applySignature(conn, body, secret);
        conn.setDoOutput(true);
        try (OutputStream os = conn.getOutputStream()) {
            os.write(body.getBytes(StandardCharsets.UTF_8));
        }
        return conn.getResponseCode();
    }

    /**
     * Opens the webhook connection with redirect-following disabled (so a malicious endpoint
     * cannot 3xx-redirect past the SSRF guard into an internal address). For {@code http} the
     * connection is pinned to {@code pinned} — the exact IP validated by the SSRF guard — and the
     * original host is sent in the {@code Host} header, closing the DNS-rebinding window. For
     * {@code https} the original URL is used so TLS SNI and certificate hostname verification
     * still work; that path relies on validate-immediately-before-connect plus disabled redirects.
     */
    private static HttpURLConnection openConnection(String url, InetAddress pinned) throws java.io.IOException, URISyntaxException {
        URL original = URI.create(url).toURL();
        HttpURLConnection conn;
        if ("http".equalsIgnoreCase(original.getProtocol()) && pinned != null) {
            int port = original.getPort() >= 0 ? original.getPort() : original.getDefaultPort();
            String literal = pinned.getHostAddress();
            String hostForUrl = (pinned instanceof Inet6Address) ? "[" + literal + "]" : literal;
            URL pinnedUrl = new URI(original.getProtocol(), null, hostForUrl, port, original.getFile(), null, null).toURL();
            conn = (HttpURLConnection) pinnedUrl.openConnection();
            String hostHeader = original.getPort() >= 0
                    ? original.getHost() + ":" + original.getPort()
                    : original.getHost();
            conn.setRequestProperty("Host", hostHeader.toLowerCase(Locale.ROOT));
        } else {
            conn = (HttpURLConnection) original.openConnection();
        }
        conn.setInstanceFollowRedirects(false);
        return conn;
    }

    private static void applySignature(HttpURLConnection conn, String body, String secret) {
        if (StringUtils.isBlank(secret)) {
            return;
        }
        String sig = hmacSha256Hex(body, secret);
        if (sig != null) {
            conn.setRequestProperty("X-BFLP-Signature", "sha256=" + sig);
        }
    }

    private static String buildJson(BanContext ctx, String event) {
        // Top-level "text" makes the payload Slack-compatible (Slack rejects payloads without
        // it with HTTP 400). Other consumers can keep parsing the structured fields.
        String text = "BFLP: IP " + ctx.getIp() + " " + event
                + " (jail " + ctx.getJailName() + ", banCount " + ctx.getBanCount() + ")";
        StringBuilder sb = new StringBuilder(320);
        sb.append("{");
        sb.append("\"event\":\"").append(jsonEscape(event)).append("\",");
        sb.append("\"text\":\"").append(jsonEscape(text)).append("\",");
        sb.append("\"ip\":\"").append(jsonEscape(ctx.getIp())).append("\",");
        sb.append("\"jail\":\"").append(jsonEscape(ctx.getJailName())).append("\",");
        sb.append("\"source\":").append(jsonNullableString(ctx.getSourceName())).append(",");
        sb.append("\"banCount\":").append(ctx.getBanCount()).append(",");
        sb.append("\"bannedAt\":").append(ctx.getBannedAt()).append(",");
        sb.append("\"bannedUntil\":").append(ctx.getBannedUntil()).append(",");
        sb.append("\"reason\":").append(jsonNullableString(ctx.getReason()));
        sb.append("}");
        return sb.toString();
    }

    /**
     * Returns the JSON representation of a nullable string field: {@code null} literal when the
     * value is absent, or a quoted and escaped JSON string when present. This lets consumers
     * distinguish a missing value from an explicitly empty string.
     */
    private static String jsonNullableString(String s) {
        if (s == null) return "null";
        return "\"" + jsonEscape(s) + "\"";
    }

    private static String jsonEscape(String s) {
        if (s == null) return "";
        StringBuilder out = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\': out.append("\\\\"); break;
                case '"':  out.append("\\\""); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
            }
        }
        return out.toString();
    }

    private static String hmacSha256Hex(String body, String secret) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] hash = mac.doFinal(body.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                hex.append(String.format("%02x", b & 0xFF));
            }
            return hex.toString();
        } catch (Exception e) {
            LOGGER.debug("BFLP: HMAC computation failed: {}", e.getMessage());
            return null;
        }
    }
}
