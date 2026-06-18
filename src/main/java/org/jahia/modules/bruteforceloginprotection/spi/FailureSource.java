package org.jahia.modules.bruteforceloginprotection.spi;

/**
 * Marker interface for OSGi components that detect login (or other authentication) failures
 * and record them for brute-force detection.
 *
 * <p><b>Built-in Implementation:</b> The module ships {@code AuthValveFailureSource}, which
 * intercepts Jahia's authentication valve chain and detects failures across multiple schemes
 * (form login, HTTP Basic, API tokens, etc.) via registered {@code AuthFailureDetector}
 * implementations.
 *
 * <p><b>Custom Failure Sources:</b> Third-party modules can register their own {@code FailureSource}
 * implementations to track authentication failures from custom authentication schemes (LDAP, OAuth,
 * 2FA, etc.). A custom source obtains a reference to {@code FailureRecorder} and calls
 * {@code recordEvent(FailureEvent)} for each detected failure:
 *
 * <pre>
 * &#64;Component(service = FailureSource.class, immediate = true)
 * public class MyCustomFailureSource implements FailureSource {
 *     &#64;Reference
 *     private FailureRecorder failureRecorder;
 *
 *     &#64;Override
 *     public String getName() {
 *         return "my-custom-auth-scheme";
 *     }
 *
 *     public void onAuthFailure(String clientIp, String username, long timestampMs) {
 *         FailureEvent event = FailureEvent.builder(clientIp)
 *             .username(username)
 *             .jailName("my-jail")
 *             .source(getName())
 *             .timestampMs(timestampMs)
 *             .build();
 *         failureRecorder.recordEvent(event);
 *     }
 * }
 * </pre>
 *
 * <p><b>Jail Name Convention:</b> Custom sources should use a meaningful jail name (e.g.,
 * "ldap-auth", "oauth-provider-a") so operators can configure separate threshold and ban
 * duration policies for each authentication scheme. If a jail with the given name does not exist,
 * a default jail is used.
 *
 * <p><b>Username Considerations:</b> Avoid including bearer tokens or API keys in the username
 * field — they end up in the audit log. Use a placeholder like "api-token-user" or "oauth-user"
 * instead.
 */
public interface FailureSource {
    /**
     * Returns a unique identifier for this failure source (e.g., "auth-valve", "ldap-auth").
     * Used for logging and audit trail records.
     */
    String getName();
}
