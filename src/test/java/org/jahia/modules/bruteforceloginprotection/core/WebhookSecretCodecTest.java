package org.jahia.modules.bruteforceloginprotection.core;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link WebhookSecretCodec} covering the null-safety, legacy-plaintext tolerance and
 * {@code {enc}}-marker detection paths. These do not exercise Jahia's {@code EncryptionUtils}
 * (which requires a running platform); the encrypt/decrypt round-trip is covered by E2E.
 */
public class WebhookSecretCodecTest {

    @Test
    public void encryptNullReturnsNull() {
        assertThat(WebhookSecretCodec.encrypt(null)).isNull();
    }

    @Test
    public void decryptNullReturnsNull() {
        assertThat(WebhookSecretCodec.decrypt(null)).isNull();
    }

    @Test
    public void decryptLegacyPlaintextPassesThrough() {
        // A value without the {enc} marker (e.g. operator-pasted) must be returned unchanged.
        assertThat(WebhookSecretCodec.decrypt("legacy-plaintext-secret")).isEqualTo("legacy-plaintext-secret");
    }

    @Test
    public void isEncryptedDetectsMarker() {
        assertThat(WebhookSecretCodec.isEncrypted("{enc}ciphertext")).isTrue();
        assertThat(WebhookSecretCodec.isEncrypted("plaintext")).isFalse();
        assertThat(WebhookSecretCodec.isEncrypted("")).isFalse();
        assertThat(WebhookSecretCodec.isEncrypted(null)).isFalse();
    }
}
