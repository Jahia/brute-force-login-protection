package org.jahia.modules.bruteforceloginprotection;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Direct tests for {@link CidrMatcher#isIpLiteral(String)} — the lexical check used to keep
 * hostnames/garbage out of code paths that must not trigger DNS resolution (X-Forwarded-For
 * parsing and manual bans). It is a character-class gate (digits/dots, or hex/colons for IPv6),
 * not a full range-validating parser.
 */
public class CidrMatcherIpLiteralTest {

    @Test
    public void acceptsIpv4Literals() {
        assertThat(CidrMatcher.isIpLiteral("192.168.1.1")).isTrue();
        assertThat(CidrMatcher.isIpLiteral("8.8.8.8")).isTrue();
        assertThat(CidrMatcher.isIpLiteral("0.0.0.0")).isTrue();
    }

    @Test
    public void acceptsIpv6Literals() {
        assertThat(CidrMatcher.isIpLiteral("::1")).isTrue();
        assertThat(CidrMatcher.isIpLiteral("2001:db8::1")).isTrue();
        assertThat(CidrMatcher.isIpLiteral("fe80::1")).isTrue();
    }

    @Test
    public void rejectsHostnames() {
        assertThat(CidrMatcher.isIpLiteral("example.com")).isFalse();
        assertThat(CidrMatcher.isIpLiteral("localhost")).isFalse();
        assertThat(CidrMatcher.isIpLiteral("evil.attacker.test")).isFalse();
    }

    @Test
    public void rejectsGarbageEmptyAndNull() {
        assertThat(CidrMatcher.isIpLiteral("not-an-ip")).isFalse();
        assertThat(CidrMatcher.isIpLiteral("192.168.1.1x")).isFalse();
        assertThat(CidrMatcher.isIpLiteral("10.0.0.1 ; rm -rf")).isFalse();
        assertThat(CidrMatcher.isIpLiteral("")).isFalse();
        assertThat(CidrMatcher.isIpLiteral(null)).isFalse();
    }
}
