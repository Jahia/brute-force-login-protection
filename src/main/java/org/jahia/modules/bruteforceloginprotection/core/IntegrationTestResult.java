package org.jahia.modules.bruteforceloginprotection.core;

public final class IntegrationTestResult {

    private final boolean success;
    private final String message;

    public IntegrationTestResult(boolean success, String message) {
        this.success = success;
        this.message = message;
    }

    public static IntegrationTestResult ok(String message) {
        return new IntegrationTestResult(true, message);
    }

    public static IntegrationTestResult fail(String message) {
        return new IntegrationTestResult(false, message);
    }

    public boolean isSuccess() {
        return success;
    }

    public String getMessage() {
        return message;
    }
}
