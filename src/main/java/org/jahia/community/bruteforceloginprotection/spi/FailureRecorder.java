package org.jahia.community.bruteforceloginprotection.spi;

public interface FailureRecorder {
    void recordEvent(FailureEvent event);

    boolean isIpCurrentlyBanned(String ip);
}
