package org.jahia.modules.bruteforceloginprotection.actions;

import org.jahia.modules.bruteforceloginprotection.core.BanContext;
import org.junit.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Unit tests for the pure-logic helpers in {@link WebhookBanAction}:
 *   - hmacSha256Hex  (HMAC-SHA256 against a known vector)
 *   - jsonEscape     (JSON string escaping)
 *   - buildJson      (full payload shape)
 *   - applySignature (header set / not set based on secret)
 *
 * All three methods are private/static; they are exercised via reflection so we never need
 * a running OSGi container, Hazelcast, or network connection.
 */
public class WebhookBanActionTest {

    // -------------------------------------------------------------------------
    // Reflection helpers
    // -------------------------------------------------------------------------

    private static String hmacSha256Hex(String body, String secret) throws Exception {
        Method m = WebhookBanAction.class.getDeclaredMethod("hmacSha256Hex", String.class, String.class);
        m.setAccessible(true);
        return (String) m.invoke(null, body, secret);
    }

    private static String jsonEscape(String s) throws Exception {
        Method m = WebhookBanAction.class.getDeclaredMethod("jsonEscape", String.class);
        m.setAccessible(true);
        return (String) m.invoke(null, s);
    }

    private static String buildJson(BanContext ctx, String event) throws Exception {
        Method m = WebhookBanAction.class.getDeclaredMethod("buildJson", BanContext.class, String.class);
        m.setAccessible(true);
        return (String) m.invoke(null, ctx, event);
    }

    private static void applySignature(HttpURLConnection conn, String body, String secret) throws Exception {
        Method m = WebhookBanAction.class.getDeclaredMethod(
                "applySignature", HttpURLConnection.class, String.class, String.class);
        m.setAccessible(true);
        m.invoke(null, conn, body, secret);
    }

    // -------------------------------------------------------------------------
    // hmacSha256Hex — known vector
    // -------------------------------------------------------------------------

    /**
     * Reference vector: HMAC-SHA256("Hello, World!", "secret")
     * Computed independently with Python:
     *   import hmac, hashlib
     *   hmac.new(b"secret", b"Hello, World!", hashlib.sha256).hexdigest()
     * = "4a313e3ce3e5e1aeb3bb2078d2e0c24b082ace01b9a36c8c6c0b47c57a51c4bd"  (NOT used — see below)
     *
     * We compute the expected value via the JDK Mac API directly so the test is
     * self-contained and independent of any external tool.
     */
    @Test
    public void hmacSha256Hex_knownVector_matchesJdkMac() throws Exception {
        String body   = "Hello, World!";
        String secret = "s3cr3t-key";

        // Compute expected with JDK directly
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        byte[] hash = mac.doFinal(body.getBytes(StandardCharsets.UTF_8));
        StringBuilder expected = new StringBuilder(hash.length * 2);
        for (byte b : hash) {
            expected.append(String.format("%02x", b & 0xFF));
        }

        String actual = hmacSha256Hex(body, secret);

        assertThat(actual).isEqualTo(expected.toString());
        assertThat(actual).hasSize(64); // SHA-256 = 32 bytes = 64 hex chars
        assertThat(actual).matches("[0-9a-f]{64}");
    }

    @Test
    public void hmacSha256Hex_emptyBody_returnsValidHex() throws Exception {
        String result = hmacSha256Hex("", "key");
        assertThat(result).isNotNull().hasSize(64).matches("[0-9a-f]{64}");
    }

    @Test
    public void hmacSha256Hex_differentSecrets_produceDifferentHashes() throws Exception {
        String h1 = hmacSha256Hex("same body", "secret1");
        String h2 = hmacSha256Hex("same body", "secret2");
        assertThat(h1).isNotEqualTo(h2);
    }

    @Test
    public void hmacSha256Hex_differentBodies_produceDifferentHashes() throws Exception {
        String h1 = hmacSha256Hex("body1", "key");
        String h2 = hmacSha256Hex("body2", "key");
        assertThat(h1).isNotEqualTo(h2);
    }

    // -------------------------------------------------------------------------
    // jsonEscape
    // -------------------------------------------------------------------------

    @Test
    public void jsonEscape_null_returnsEmpty() throws Exception {
        assertThat(jsonEscape(null)).isEqualTo("");
    }

    @Test
    public void jsonEscape_cleanString_unchanged() throws Exception {
        assertThat(jsonEscape("hello world")).isEqualTo("hello world");
    }

    @Test
    public void jsonEscape_doubleQuote_escaped() throws Exception {
        assertThat(jsonEscape("say \"hi\"")).isEqualTo("say \\\"hi\\\"");
    }

    @Test
    public void jsonEscape_backslash_escaped() throws Exception {
        assertThat(jsonEscape("C:\\path")).isEqualTo("C:\\\\path");
    }

    @Test
    public void jsonEscape_newline_escaped() throws Exception {
        assertThat(jsonEscape("line1\nline2")).isEqualTo("line1\\nline2");
    }

    @Test
    public void jsonEscape_carriageReturn_escaped() throws Exception {
        assertThat(jsonEscape("foo\rbar")).isEqualTo("foo\\rbar");
    }

    @Test
    public void jsonEscape_tab_escaped() throws Exception {
        assertThat(jsonEscape("col1\tcol2")).isEqualTo("col1\\tcol2");
    }

    @Test
    public void jsonEscape_controlCharBelow0x20_unicodeEscaped() throws Exception {
        // char 0x01 (SOH) must become 
        assertThat(jsonEscape("")).isEqualTo("\\u0001");
    }

    @Test
    public void jsonEscape_char0x1f_unicodeEscaped() throws Exception {
        assertThat(jsonEscape("")).isEqualTo("\\u001f");
    }

    @Test
    public void jsonEscape_combinedSpecialChars() throws Exception {
        String result = jsonEscape("\"back\\slash\"\nnewline");
        assertThat(result).isEqualTo("\\\"back\\\\slash\\\"\\nnewline");
    }

    // -------------------------------------------------------------------------
    // buildJson — shape and escaping
    // -------------------------------------------------------------------------

    private BanContext sampleContext() {
        return BanContext.builder()
                .ip("192.168.1.1")
                .jailName("login")
                .sourceName("form")
                .bannedAt(1_000_000L)
                .bannedUntil(2_000_000L)
                .banCount(3)
                .reason("exceeded retries")
                .build();
    }

    @Test
    public void buildJson_containsRequiredFields() throws Exception {
        String json = buildJson(sampleContext(), "ban");
        assertThat(json)
                .contains("\"event\":\"ban\"")
                .contains("\"ip\":\"192.168.1.1\"")
                .contains("\"jail\":\"login\"")
                .contains("\"source\":\"form\"")
                .contains("\"banCount\":3")
                .contains("\"bannedAt\":1000000")
                .contains("\"bannedUntil\":2000000")
                .contains("\"reason\":\"exceeded retries\"");
    }

    @Test
    public void buildJson_containsTextFieldForSlackCompatibility() throws Exception {
        String json = buildJson(sampleContext(), "ban");
        assertThat(json).contains("\"text\":");
    }

    @Test
    public void buildJson_specialCharsInIp_escaped() throws Exception {
        BanContext ctx = BanContext.builder()
                .ip("192.168.1.1")
                .jailName("jail\"name")    // double-quote in jail name
                .sourceName("src")
                .bannedAt(0L).bannedUntil(0L).banCount(1).reason("r")
                .build();
        String json = buildJson(ctx, "ban");
        // The quote in jailName must be escaped in the JSON output
        assertThat(json).contains("\"jail\":\"jail\\\"name\"");
    }

    @Test
    public void buildJson_unbanEvent_setsCorrectEvent() throws Exception {
        String json = buildJson(sampleContext(), "unban");
        assertThat(json).contains("\"event\":\"unban\"");
    }

    // -------------------------------------------------------------------------
    // applySignature
    // -------------------------------------------------------------------------

    @Test
    public void applySignature_blankSecret_noHeaderSet() throws Exception {
        HttpURLConnection conn = mock(HttpURLConnection.class);
        applySignature(conn, "body", "");
        verifyNoInteractions(conn);
    }

    @Test
    public void applySignature_nullSecret_noHeaderSet() throws Exception {
        HttpURLConnection conn = mock(HttpURLConnection.class);
        applySignature(conn, "body", null);
        verifyNoInteractions(conn);
    }

    @Test
    public void applySignature_validSecret_setsSignatureHeader() throws Exception {
        HttpURLConnection conn = mock(HttpURLConnection.class);
        String body   = "{\"event\":\"ban\"}";
        String secret = "my-webhook-secret";
        applySignature(conn, body, secret);
        // Verify the header was set with sha256= prefix
        verify(conn).setRequestProperty(
                org.mockito.ArgumentMatchers.eq("X-BFLP-Signature"),
                org.mockito.ArgumentMatchers.startsWith("sha256="));
    }

    @Test
    public void applySignature_headerValueMatchesHmac() throws Exception {
        HttpURLConnection conn = mock(HttpURLConnection.class);
        String body   = "{\"event\":\"ban\"}";
        String secret = "my-webhook-secret";

        String expectedHmac = hmacSha256Hex(body, secret);

        org.mockito.ArgumentCaptor<String> valueCaptor =
                org.mockito.ArgumentCaptor.forClass(String.class);
        applySignature(conn, body, secret);

        verify(conn).setRequestProperty(
                org.mockito.ArgumentMatchers.eq("X-BFLP-Signature"),
                valueCaptor.capture());

        assertThat(valueCaptor.getValue()).isEqualTo("sha256=" + expectedHmac);
    }
}
