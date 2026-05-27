package org.jahia.modules.bruteforceloginprotection;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class CidrMatcherTest {

    @Test
    public void ipv4HostInSubnetMatches() {
        CidrMatcher m = new CidrMatcher("192.168.1.0/24");
        assertThat(m.matches("192.168.1.5")).isTrue();
        assertThat(m.matches("192.168.1.255")).isTrue();
    }

    @Test
    public void ipv4HostOutsideSubnetDoesNotMatch() {
        CidrMatcher m = new CidrMatcher("192.168.1.0/24");
        assertThat(m.matches("192.168.2.1")).isFalse();
        assertThat(m.matches("10.0.0.1")).isFalse();
    }

    @Test
    public void ipv4SingleHost32MatchesOnlyItself() {
        CidrMatcher m = new CidrMatcher("127.0.0.1/32");
        assertThat(m.matches("127.0.0.1")).isTrue();
        assertThat(m.matches("127.0.0.2")).isFalse();
    }

    @Test
    public void ipv6LoopbackMatch() {
        CidrMatcher m = new CidrMatcher("::1/128");
        assertThat(m.matches("::1")).isTrue();
        assertThat(m.matches("::2")).isFalse();
    }

    @Test
    public void ipv6PrefixMatch() {
        CidrMatcher m = new CidrMatcher("2001:db8::/32");
        assertThat(m.matches("2001:db8:1234::1")).isTrue();
        assertThat(m.matches("2001:db9::1")).isFalse();
    }

    @Test
    public void invalidCidrThrows() {
        assertThatThrownBy(() -> new CidrMatcher("not-an-ip/24"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new CidrMatcher("192.168.1.0/abc"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new CidrMatcher("192.168.1.0/99"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    public void hostnameAddressPartIsRejected() {
        // Must not fall through to a DNS lookup on config-supplied input.
        assertThatThrownBy(() -> new CidrMatcher("example.com/24"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new CidrMatcher("localhost"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    public void mixedFamilyDoesNotMatch() {
        CidrMatcher m = new CidrMatcher("2001:db8::/32");
        assertThat(m.matches("192.168.1.1")).isFalse();
    }

    @Test
    public void matchesNullReturnsFalse() {
        CidrMatcher m = new CidrMatcher("192.168.1.0/24");
        assertThat(m.matches(null)).isFalse();
    }
}
