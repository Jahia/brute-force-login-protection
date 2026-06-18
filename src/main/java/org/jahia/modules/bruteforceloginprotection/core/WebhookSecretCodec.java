package org.jahia.modules.bruteforceloginprotection.core;

import org.jahia.utils.EncryptionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Encodes/decodes the webhook secret with a stable {@code {enc}} marker so operators can paste a
 * plaintext value into the OSGi .cfg and the module will transparently re-encrypt it on the next
 * save. Decryption tolerates legacy plaintext values (no marker).
 */
public final class WebhookSecretCodec {

    private static final Logger LOGGER = LoggerFactory.getLogger(WebhookSecretCodec.class);
    private static final String ENC_PREFIX = "{enc}";

    private WebhookSecretCodec() {
        // utility
    }

    /**
     * Encrypts {@code plain} and returns the {@code {enc}}-prefixed ciphertext.
     *
     * @throws IllegalStateException if encryption fails — callers must not persist the secret when
     *                               this method throws, as that would store plaintext in the .cfg.
     */
    public static String encrypt(String plain) {
        if (plain == null) {
            return null;
        }
        try {
            return ENC_PREFIX + EncryptionUtils.passwordBaseEncrypt(plain);
        } catch (Exception e) {
            // Rethrow with context (preserving the cause) instead of logging-and-rethrowing:
            // callers must NOT persist the secret when this throws (that would store plaintext),
            // and the wrapping exception carries everything the caller needs to log once.
            throw new IllegalStateException(
                    "BFLP: webhookSecret encryption failed — refusing to persist plaintext", e);
        }
    }

    public static String decrypt(String stored) {
        if (stored == null || !stored.startsWith(ENC_PREFIX)) {
            return stored; // legacy plaintext (e.g. operator-pasted) or null
        }
        try {
            return EncryptionUtils.passwordBaseDecrypt(stored.substring(ENC_PREFIX.length()));
        } catch (Exception e) {
            LOGGER.warn("BFLP: failed to decrypt webhookSecret: {}", e.getMessage());
            return null;
        }
    }

    public static boolean isEncrypted(String stored) {
        return stored != null && stored.startsWith(ENC_PREFIX);
    }
}
