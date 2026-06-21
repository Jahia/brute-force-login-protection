package org.jahia.community.bruteforceloginprotection.core;

/**
 * Immutable outcome of an integration "send test" (email or webhook), surfaced to the admin UI
 * via the {@code testEmail}/{@code testWebhook} GraphQL mutations.
 */
public record IntegrationTestResult(boolean success, String message) {

    public static IntegrationTestResult ok(String message) {
        return new IntegrationTestResult(true, message);
    }

    public static IntegrationTestResult fail(String message) {
        return new IntegrationTestResult(false, message);
    }
}
