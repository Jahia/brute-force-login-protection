package org.jahia.modules.bruteforceloginprotection.spi;

/**
 * Marker interface. Implementations are OSGi components that detect login (or other)
 * failures and feed them into the FailureRecorder.
 */
public interface FailureSource {
    String getName();
}
