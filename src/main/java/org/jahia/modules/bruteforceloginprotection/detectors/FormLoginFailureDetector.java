package org.jahia.modules.bruteforceloginprotection.detectors;

import org.jahia.modules.bruteforceloginprotection.BruteForceLoginProtectionConstants;
import org.jahia.modules.bruteforceloginprotection.spi.AuthFailureContext;
import org.jahia.modules.bruteforceloginprotection.spi.AuthFailureDetector;
import org.jahia.modules.bruteforceloginprotection.spi.FailureSignal;
import org.jahia.params.valves.LoginEngineAuthValveImpl;
import org.osgi.service.component.annotations.Component;

import javax.servlet.http.HttpServletRequest;

/**
 * Detects standard form-login failures by reading the {@code VALVE_RESULT} request attribute.
 * Covers {@link LoginEngineAuthValveImpl} and every {@code SsoValve} subclass — both set
 * {@code BAD_PASSWORD} / {@code UNKNOWN_USER} on the request.
 */
@Component(service = AuthFailureDetector.class, immediate = true)
public class FormLoginFailureDetector implements AuthFailureDetector {

    @Override
    public FailureSignal detect(AuthFailureContext context) {
        HttpServletRequest request = context.request();
        Object result = request.getAttribute(LoginEngineAuthValveImpl.VALVE_RESULT);
        if (result == null) {
            return null;
        }
        if (!LoginEngineAuthValveImpl.BAD_PASSWORD.equals(result)
                && !LoginEngineAuthValveImpl.UNKNOWN_USER.equals(result)) {
            return null;
        }
        // Pass the raw username unchanged so audit logs preserve the original case. Normalization
        // for ignore-pattern matching happens centrally in BruteForceTracker.matchesIgnorePattern,
        // keeping matching consistent across all auth methods without lowercasing the audit trail.
        return FailureSignal.builder(BruteForceLoginProtectionConstants.DEFAULT_JAIL_LOGIN)
                .username(request.getParameter("username"))
                .extra("result", String.valueOf(result))
                .build();
    }

    @Override
    public int order() {
        return 100;
    }
}
