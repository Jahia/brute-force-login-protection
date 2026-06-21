package org.jahia.community.bruteforceloginprotection.detectors;

import org.jahia.community.bruteforceloginprotection.spi.AuthFailureContext;
import org.jahia.community.bruteforceloginprotection.spi.AuthFailureDetector;
import org.jahia.community.bruteforceloginprotection.spi.FailureSignal;
import org.osgi.service.component.annotations.Component;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Detects failed HTTP Basic auth attempts from {@code HttpBasicAuthValveImpl}, which silently
 * leaves the request unauthenticated on bad credentials (no VALVE_RESULT, no login event).
 */
@Component(service = AuthFailureDetector.class, immediate = true)
public class BasicAuthFailureDetector implements AuthFailureDetector {

    public static final String SOURCE_NAME = "basic-auth-valve";
    private static final String BASIC_PREFIX = "Basic ";

    @Override
    public FailureSignal detect(AuthFailureContext context) {
        if (context.authenticated()) {
            return null;
        }
        String authHeader = context.request().getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith(BASIC_PREFIX)) {
            return null;
        }
        return FailureSignal.builder(SOURCE_NAME)
                .username(extractUsername(authHeader))
                .extra("authScheme", "basic")
                .build();
    }

    @Override
    public int order() {
        return 200;
    }

    private static String extractUsername(String authHeader) {
        try {
            String encoded = authHeader.substring(BASIC_PREFIX.length()).trim();
            String decoded = new String(Base64.getDecoder().decode(encoded), StandardCharsets.UTF_8);
            int colon = decoded.indexOf(':');
            if (colon <= 0) {
                return null;
            }
            return decoded.substring(0, colon);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
