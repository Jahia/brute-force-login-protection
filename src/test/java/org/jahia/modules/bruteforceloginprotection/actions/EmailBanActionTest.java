package org.jahia.modules.bruteforceloginprotection.actions;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link EmailBanAction#stripHeaderInjection(String)}.
 *
 * stripHeaderInjection is package-private (static), so the test lives in the same package.
 * No OSGi/JCR runtime is required.
 */
public class EmailBanActionTest {

    // -------------------------------------------------------------------------
    // Null safety
    // -------------------------------------------------------------------------

    @Test
    public void stripHeaderInjection_null_returnsNull() {
        assertThat(EmailBanAction.stripHeaderInjection(null)).isNull();
    }

    // -------------------------------------------------------------------------
    // Clean value unchanged
    // -------------------------------------------------------------------------

    @Test
    public void stripHeaderInjection_cleanValue_returnedUnchanged() {
        String clean = "admin@example.com";
        assertThat(EmailBanAction.stripHeaderInjection(clean)).isEqualTo(clean);
    }

    @Test
    public void stripHeaderInjection_emptyString_returnsEmpty() {
        assertThat(EmailBanAction.stripHeaderInjection("")).isEmpty();
    }

    // -------------------------------------------------------------------------
    // Literal CR / LF
    // -------------------------------------------------------------------------

    @Test
    public void stripHeaderInjection_literalCR_stripped() {
        assertThat(EmailBanAction.stripHeaderInjection("foo\rbar")).isEqualTo("foobar");
    }

    @Test
    public void stripHeaderInjection_literalLF_stripped() {
        assertThat(EmailBanAction.stripHeaderInjection("foo\nbar")).isEqualTo("foobar");
    }

    @Test
    public void stripHeaderInjection_literalCRLF_stripped() {
        assertThat(EmailBanAction.stripHeaderInjection("Subject: x\r\nBcc: attacker@evil.com"))
                .isEqualTo("Subject: xBcc: attacker@evil.com");
    }

    // -------------------------------------------------------------------------
    // Percent-encoded variants
    // -------------------------------------------------------------------------

    @Test
    public void stripHeaderInjection_percentEncodedLFLowercase_stripped() {
        assertThat(EmailBanAction.stripHeaderInjection("foo%0abar")).isEqualTo("foobar");
    }

    @Test
    public void stripHeaderInjection_percentEncodedLFUppercase_stripped() {
        assertThat(EmailBanAction.stripHeaderInjection("foo%0Abar")).isEqualTo("foobar");
    }

    @Test
    public void stripHeaderInjection_percentEncodedCRLowercase_stripped() {
        assertThat(EmailBanAction.stripHeaderInjection("foo%0dbar")).isEqualTo("foobar");
    }

    @Test
    public void stripHeaderInjection_percentEncodedCRUppercase_stripped() {
        assertThat(EmailBanAction.stripHeaderInjection("foo%0Dbar")).isEqualTo("foobar");
    }

    // -------------------------------------------------------------------------
    // Mixed injection attempt
    // -------------------------------------------------------------------------

    @Test
    public void stripHeaderInjection_mixedInjectionAttempt_allStripped() {
        String injected = "valid@example.com%0d%0aBcc: spy@evil.com\r\nX-Injected: yes";
        String result = EmailBanAction.stripHeaderInjection(injected);
        assertThat(result)
                .doesNotContain("\r")
                .doesNotContain("\n")
                .doesNotContain("%0d")
                .doesNotContain("%0D")
                .doesNotContain("%0a")
                .doesNotContain("%0A")
                .isEqualTo("valid@example.comBcc: spy@evil.comX-Injected: yes");
    }

    // -------------------------------------------------------------------------
    // Only CR/LF sequences stripped — other content preserved
    // -------------------------------------------------------------------------

    @Test
    public void stripHeaderInjection_preservesOtherSpecialChars() {
        String value = "user+tag@sub.example.com";
        assertThat(EmailBanAction.stripHeaderInjection(value)).isEqualTo(value);
    }

    @Test
    public void stripHeaderInjection_percentEncodedOtherChars_notStripped() {
        // %40 is '@'; it is NOT in the strip list and must survive
        String value = "user%40example.com";
        assertThat(EmailBanAction.stripHeaderInjection(value)).isEqualTo(value);
    }
}
