package org.jahia.community.bruteforceloginprotection.actions;

import org.junit.Test;

import java.net.InetAddress;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * SSRF-mitigation tests for {@link WebhookUrlValidator}. All cases use IP literals so the
 * validator resolves them without real DNS, keeping the test hermetic. Forbidden cases assert
 * an {@link IllegalArgumentException} is thrown (the exact message/reason may differ per JDK for
 * IPv6 literals, so only the type is asserted there).
 */
public class WebhookUrlValidatorTest {

    @Test
    public void blankOrNullRejected() {
        assertThatThrownBy(() -> WebhookUrlValidator.validateUrl("")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> WebhookUrlValidator.validateUrl(null)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    public void missingSchemeRejected() {
        assertThatThrownBy(() -> WebhookUrlValidator.validateUrl("8.8.8.8/hook"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    public void nonHttpsSchemeRejected() {
        assertThatThrownBy(() -> WebhookUrlValidator.validateUrl("ftp://8.8.8.8/"))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("https");
        assertThatThrownBy(() -> WebhookUrlValidator.validateUrl("file:///etc/passwd"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    public void httpRejectedByDefault() {
        assertThatThrownBy(() -> WebhookUrlValidator.validateUrl("http://8.8.8.8/"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    public void userinfoRejected() {
        assertThatThrownBy(() -> WebhookUrlValidator.validateUrl("https://user:pass@8.8.8.8/"))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("userinfo");
    }

    @Test
    public void loopbackRejected() {
        assertThatThrownBy(() -> WebhookUrlValidator.validateUrl("https://127.0.0.1/"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> WebhookUrlValidator.validateUrl("https://[::1]/"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    public void cloudMetadataAddressRejected() {
        assertThatThrownBy(() -> WebhookUrlValidator.validateUrl("https://169.254.169.254/latest/meta-data/"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    public void privateIpv4RangesRejected() {
        assertThatThrownBy(() -> WebhookUrlValidator.validateUrl("https://10.0.0.5/")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> WebhookUrlValidator.validateUrl("https://192.168.1.10/")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> WebhookUrlValidator.validateUrl("https://172.16.5.5/")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    public void anyLocalAddressRejected() {
        assertThatThrownBy(() -> WebhookUrlValidator.validateUrl("https://0.0.0.0/"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    public void ipv6InternalRangesRejected() {
        // unique-local (fc00::/7) and link-local (fe80::/10)
        assertThatThrownBy(() -> WebhookUrlValidator.validateUrl("https://[fc00::1]/")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> WebhookUrlValidator.validateUrl("https://[fd12::1]/")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> WebhookUrlValidator.validateUrl("https://[fe80::1]/")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    public void ipv4MappedLoopbackRejected() {
        assertThatThrownBy(() -> WebhookUrlValidator.validateUrl("https://[::ffff:127.0.0.1]/"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    public void multicastAddressRejected() {
        // F7 residual: no existing test rejects a multicast address (224.0.0.0/4, ff00::/8).
        assertThatThrownBy(() -> WebhookUrlValidator.validateUrl("https://224.0.0.1/"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> WebhookUrlValidator.validateUrl("https://[ff02::1]/"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    public void publicHttpsAddressAccepted() {
        InetAddress addr = WebhookUrlValidator.validateAndResolve("https://8.8.8.8/hook");
        assertThat(addr.getHostAddress()).isEqualTo("8.8.8.8");
        assertThatCode(() -> WebhookUrlValidator.validateUrl("https://93.184.216.34:8443/hook"))
                .doesNotThrowAnyException();
    }
}
