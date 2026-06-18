package org.jahia.modules.bruteforceloginprotection.detectors;

import org.jahia.modules.bruteforceloginprotection.spi.AuthFailureContext;
import org.jahia.modules.bruteforceloginprotection.spi.AuthFailureDetector;
import org.jahia.modules.bruteforceloginprotection.spi.FailureSignal;
import org.osgi.service.component.annotations.Component;

/**
 * Detects failed Personal API token attempts from the {@code personal-api-tokens} module's
 * {@code TokenAuthValve}. Like Basic auth it sets no VALVE_RESULT — we infer failure from the
 * unauthenticated post-chain state plus the {@code APIToken} prefix on the Authorization header.
 * The token itself is a bearer secret and is deliberately not propagated as a username.
 */
@Component(service = AuthFailureDetector.class, immediate = true)
public class ApiTokenAuthFailureDetector implements AuthFailureDetector {

    public static final String SOURCE_NAME = "api-token-valve";
    private static final String APITOKEN_PREFIX = "APIToken ";

    @Override
    public FailureSignal detect(AuthFailureContext context) {
        if (context.authenticated()) {
            return null;
        }
        String authHeader = context.request().getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith(APITOKEN_PREFIX)) {
            return null;
        }
        return FailureSignal.builder(SOURCE_NAME)
                .extra("authScheme", "apitoken")
                .build();
    }

    @Override
    public int order() {
        return 300;
    }
}
