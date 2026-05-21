package org.jahia.modules.bruteforceloginprotection.spi;

public interface FailureRecorder {
    void record(FailureEvent event);

    boolean isIpCurrentlyBanned(String ip);
}
