package org.jahia.modules.bruteforceloginprotection.sources;

import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for the security-critical {@code X-Forwarded-For} chain parsing in
 * {@link AuthValveFailureSource}. The headline guarantee: a client can never spoof its address by
 * prepending an entry, because parsing walks right-to-left and only trusts proxy-added hops.
 */
public class ForwardedForParsingTest {

    private static final List<String> TRUSTED = Arrays.asList("10.0.0.0/8", "192.168.0.0/16");

    @Test
    public void leftmostSpoofedEntryIsIgnored_singleProxy() {
        // Attacker (real IP 203.0.113.7) sent "X-Forwarded-For: 6.6.6.6"; the proxy appended the
        // real peer. The rightmost untrusted entry is the real client.
        String header = "6.6.6.6, 203.0.113.7";
        assertThat(AuthValveFailureSource.extractClientFromForwardedChain(header, TRUSTED))
                .isEqualTo("203.0.113.7");
    }

    @Test
    public void skipsTrustedProxyHops_multipleProxies() {
        // client -> proxyA(10.0.0.2) -> proxyB(10.0.0.3) -> app
        String header = "6.6.6.6, 203.0.113.7, 10.0.0.2, 10.0.0.3";
        assertThat(AuthValveFailureSource.extractClientFromForwardedChain(header, TRUSTED))
                .isEqualTo("203.0.113.7");
    }

    @Test
    public void allEntriesTrustedReturnsNull() {
        String header = "10.0.0.2, 192.168.1.5";
        assertThat(AuthValveFailureSource.extractClientFromForwardedChain(header, TRUSTED)).isNull();
    }

    @Test
    public void malformedRightmostEntryStopsChain() {
        String header = "203.0.113.7, not-an-ip";
        assertThat(AuthValveFailureSource.extractClientFromForwardedChain(header, TRUSTED)).isNull();
    }

    @Test
    public void singleUntrustedEntryReturnedDirectly() {
        assertThat(AuthValveFailureSource.extractClientFromForwardedChain("203.0.113.7", TRUSTED))
                .isEqualTo("203.0.113.7");
    }

    @Test
    public void ipv6ClientIsParsed() {
        String header = "2001:db8::1, 10.0.0.2";
        assertThat(AuthValveFailureSource.extractClientFromForwardedChain(header, TRUSTED))
                .isEqualTo("2001:db8::1");
    }

    @Test
    public void blankEntriesAreSkipped() {
        String header = "203.0.113.7, , 10.0.0.2";
        assertThat(AuthValveFailureSource.extractClientFromForwardedChain(header, TRUSTED))
                .isEqualTo("203.0.113.7");
    }

    @Test
    public void emptyTrustedListReturnsRightmost() {
        String header = "6.6.6.6, 203.0.113.7";
        assertThat(AuthValveFailureSource.extractClientFromForwardedChain(header, Collections.emptyList()))
                .isEqualTo("203.0.113.7");
    }

    @Test
    public void ipLiteralValidationRejectsHostnamesAndGarbage() {
        assertThat(AuthValveFailureSource.isValidIpLiteral("1.2.3.4")).isTrue();
        assertThat(AuthValveFailureSource.isValidIpLiteral("::1")).isTrue();
        assertThat(AuthValveFailureSource.isValidIpLiteral("2001:db8::1")).isTrue();
        assertThat(AuthValveFailureSource.isValidIpLiteral("evil.example.com")).isFalse();
        assertThat(AuthValveFailureSource.isValidIpLiteral("1.2.3.4xyz")).isFalse();
        assertThat(AuthValveFailureSource.isValidIpLiteral("")).isFalse();
        assertThat(AuthValveFailureSource.isValidIpLiteral(null)).isFalse();
    }
}
