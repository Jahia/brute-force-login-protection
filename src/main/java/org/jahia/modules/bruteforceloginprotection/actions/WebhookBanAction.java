package org.jahia.modules.bruteforceloginprotection.actions;

import org.apache.commons.lang.StringUtils;
import org.jahia.modules.bruteforceloginprotection.core.BanContext;
import org.jahia.modules.bruteforceloginprotection.core.GlobalSettings;
import org.jahia.modules.bruteforceloginprotection.core.SettingsService;
import org.jahia.modules.bruteforceloginprotection.spi.BanAction;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;

@Component(immediate = true, service = BanAction.class)
public class WebhookBanAction implements BanAction {

    private static final Logger LOGGER = LoggerFactory.getLogger(WebhookBanAction.class);
    private static final long OVERALL_DEADLINE_SEC = 10L;
    private static final int EXECUTOR_POOL_SIZE = 2;
    private static final AtomicInteger WEBHOOK_THREAD_COUNTER = new AtomicInteger();
    private static final ExecutorService WEBHOOK_EXECUTOR = Executors.newFixedThreadPool(EXECUTOR_POOL_SIZE, r -> {
        Thread t = new Thread(r, "bflp-webhook-" + WEBHOOK_THREAD_COUNTER.incrementAndGet());
        t.setDaemon(true);
        return t;
    });

    @Reference
    private SettingsService settingsService;

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
        try {
            WebhookUrlValidator.validateUrl(url);
        } catch (IllegalArgumentException ex) {
            LOGGER.warn("BFLP: webhook URL rejected by SSRF guard: {}", ex.getMessage());
            return;
        }
        String body = buildJson(context, event);
        String secret = settings.getWebhookSecret();
        final HttpURLConnection[] connHolder = new HttpURLConnection[1];
        Future<Void> future = WEBHOOK_EXECUTOR.submit(() -> {
            try {
                URL u = new URL(url);
                HttpURLConnection conn = (HttpURLConnection) u.openConnection();
                connHolder[0] = conn;
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Content-Type", "application/json");
                conn.setRequestProperty("User-Agent", "BFLP-Webhook/1.0");
                conn.setConnectTimeout(5000);
                conn.setReadTimeout(5000);
                if (StringUtils.isNotBlank(secret)) {
                    String sig = hmacSha256Hex(body, secret);
                    if (sig != null) {
                        conn.setRequestProperty("X-BFLP-Signature", "sha256=" + sig);
                    }
                }
                conn.setDoOutput(true);
                try (OutputStream os = conn.getOutputStream()) {
                    os.write(body.getBytes(StandardCharsets.UTF_8));
                }
                int code = conn.getResponseCode();
                if (code >= 400) {
                    LOGGER.warn("BFLP: webhook returned status {}", code);
                }
                conn.disconnect();
            } catch (Exception e) {
                LOGGER.warn("BFLP: webhook delivery failed: {}", e.getMessage());
            }
            return null;
        });
        try {
            future.get(OVERALL_DEADLINE_SEC, TimeUnit.SECONDS);
        } catch (TimeoutException te) {
            future.cancel(true);
            HttpURLConnection conn = connHolder[0];
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

    private static String buildJson(BanContext ctx, String event) {
        StringBuilder sb = new StringBuilder(256);
        sb.append("{");
        sb.append("\"event\":\"").append(jsonEscape(event)).append("\",");
        sb.append("\"ip\":\"").append(jsonEscape(ctx.getIp())).append("\",");
        sb.append("\"jail\":\"").append(jsonEscape(ctx.getJailName())).append("\",");
        sb.append("\"source\":\"").append(jsonEscape(ctx.getSourceName())).append("\",");
        sb.append("\"banCount\":").append(ctx.getBanCount()).append(",");
        sb.append("\"bannedAt\":").append(ctx.getBannedAt()).append(",");
        sb.append("\"bannedUntil\":").append(ctx.getBannedUntil()).append(",");
        sb.append("\"reason\":\"").append(jsonEscape(ctx.getReason())).append("\"");
        sb.append("}");
        return sb.toString();
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
