package org.jahia.modules.bruteforceloginprotection.detectors;

import org.jahia.modules.bruteforceloginprotection.spi.AuthFailureContext;
import org.jahia.modules.bruteforceloginprotection.spi.AuthFailureDetector;
import org.jahia.modules.bruteforceloginprotection.spi.FailureSignal;
import org.osgi.service.component.annotations.Component;

/**
 * Detects failed attempts against the deprecated {@code TokenAuthValveImpl} (jahiatoken
 * header). The valve silently falls through when the token is unknown, so the signal is the
 * same as Basic / APIToken: header present + unauthenticated post-chain.
 */
@Component(service = AuthFailureDetector.class, immediate = true)
public class JahiaTokenAuthFailureDetector implements AuthFailureDetector {

    public static final String SOURCE_NAME = "jahia-token-valve";
    private static final String HEADER = "jahiatoken";

    @Override
    public FailureSignal detect(AuthFailureContext context) {
        if (context.isAuthenticated()) {
            return null;
        }
        String token = context.getRequest().getHeader(HEADER);
        if (token == null || token.isEmpty()) {
            return null;
        }
        return FailureSignal.builder(SOURCE_NAME)
                .extra("authScheme", "jahiatoken")
                .build();
    }

    @Override
    public int order() {
        return 400;
    }
}
