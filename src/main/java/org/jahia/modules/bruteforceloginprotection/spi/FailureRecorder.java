package org.jahia.modules.bruteforceloginprotection.spi;

public interface FailureRecorder {
    void recordEvent(FailureEvent event);

    boolean isIpCurrentlyBanned(String ip);
}
