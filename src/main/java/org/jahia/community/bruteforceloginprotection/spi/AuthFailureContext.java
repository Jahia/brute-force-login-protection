package org.jahia.community.bruteforceloginprotection.spi;

import org.jahia.params.valves.AuthValveContext;

import javax.servlet.http.HttpServletRequest;

/**
 * Read-only view of the auth-pipeline state that detectors examine after the chain has run.
 * Passed by {@code AuthValveFailureSource} to every registered {@link AuthFailureDetector}.
 */
public record AuthFailureContext(HttpServletRequest request, AuthValveContext authValveContext,
                                 boolean authenticated, String remoteAddress) {
}
