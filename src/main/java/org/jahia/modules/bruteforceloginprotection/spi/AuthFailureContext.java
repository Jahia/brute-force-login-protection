package org.jahia.modules.bruteforceloginprotection.spi;

import org.jahia.params.valves.AuthValveContext;

import javax.servlet.http.HttpServletRequest;

/**
 * Read-only view of the auth-pipeline state that detectors examine after the chain has run.
 * Passed by {@code AuthValveFailureSource} to every registered {@link AuthFailureDetector}.
 */
public final class AuthFailureContext {

    private final HttpServletRequest request;
    private final AuthValveContext authValveContext;
    private final boolean authenticated;
    private final String remoteAddress;

    public AuthFailureContext(HttpServletRequest request, AuthValveContext authValveContext,
                              boolean authenticated, String remoteAddress) {
        this.request = request;
        this.authValveContext = authValveContext;
        this.authenticated = authenticated;
        this.remoteAddress = remoteAddress;
    }

    public HttpServletRequest getRequest() {
        return request;
    }

    public AuthValveContext getAuthValveContext() {
        return authValveContext;
    }

    /**
     * @return true if the auth pipeline left a non-guest user on the session factory.
     */
    public boolean isAuthenticated() {
        return authenticated;
    }

    public String getRemoteAddress() {
        return remoteAddress;
    }
}
