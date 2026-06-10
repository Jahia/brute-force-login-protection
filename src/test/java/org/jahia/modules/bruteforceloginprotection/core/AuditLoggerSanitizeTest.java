package org.jahia.modules.bruteforceloginprotection.core;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link AuditLogger#sanitize(String)} — strips CR/LF so attacker-controlled values
 * (e.g. usernames) cannot inject forged lines into the audit trail / logs.
 */
public class AuditLoggerSanitizeTest {

    @Test
    public void stripsCarriageReturnAndNewline() {
        assertThat(AuditLogger.sanitize("hello\r\nworld")).isEqualTo("helloworld");
        assertThat(AuditLogger.sanitize("a\rb\nc")).isEqualTo("abc");
        assertThat(AuditLogger.sanitize("user\nBAN 1.2.3.4 forged")).isEqualTo("userBAN 1.2.3.4 forged");
    }

    @Test
    public void nullReturnsNull() {
        assertThat(AuditLogger.sanitize(null)).isNull();
    }

    @Test
    public void plainValueUnchanged() {
        assertThat(AuditLogger.sanitize("admin")).isEqualTo("admin");
        assertThat(AuditLogger.sanitize("")).isEqualTo("");
    }
}
