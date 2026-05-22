package org.jahia.modules.bruteforceloginprotection.sources;

import org.apache.commons.lang.StringUtils;
import org.jahia.modules.bruteforceloginprotection.BruteForceLoginProtectionConstants;
import org.jahia.modules.bruteforceloginprotection.CidrMatcher;
import org.jahia.modules.bruteforceloginprotection.core.GlobalSettings;
import org.jahia.modules.bruteforceloginprotection.core.SettingsService;
import org.jahia.modules.bruteforceloginprotection.spi.FailureEvent;
import org.jahia.modules.bruteforceloginprotection.spi.FailureRecorder;
import org.jahia.modules.bruteforceloginprotection.spi.FailureSource;
import org.jahia.params.valves.AuthValveContext;
import org.jahia.params.valves.BaseAuthValve;
import org.jahia.params.valves.LoginEngineAuthValveImpl;
import org.jahia.pipelines.Pipeline;
import org.jahia.pipelines.PipelineException;
import org.jahia.pipelines.valves.ValveContext;
import org.jahia.services.usermanager.JahiaUser;
import org.jahia.services.usermanager.JahiaUserManagerService;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

@Component(service = {}, immediate = true)
public final class AuthValveFailureSource extends BaseAuthValve implements FailureSource {

    private static final long serialVersionUID = 1L;
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthValveFailureSource.class);
    private static final String REMOTE_ADDRESS_HEADER = "x-forwarded-for";
    private static final String KEY_SEPARATOR = ",";
    public static final String AUTH_VALVE_ID = "bruteForceLoginProtectionAuthValve";
    private static final String BASIC_AUTH_SOURCE = "basic-auth-valve";
    private static final String BASIC_PREFIX = "Basic ";

    private final AtomicBoolean emptyTrustedProxyWarningEmitted = new AtomicBoolean(false);

    @Reference(target = "(type=authentication)")
    private Pipeline authPipeline;

    @Reference
    private FailureRecorder failureRecorder;

    @Reference
    private SettingsService settingsService;

    public AuthValveFailureSource() {
        super();
    }

    @Override
    public String getName() {
        return BruteForceLoginProtectionConstants.DEFAULT_JAIL_LOGIN;
    }

    @Activate
    public void start() {
        setId(AUTH_VALVE_ID);
        removeValve(authPipeline);
        addValve(authPipeline, 0, null, null);
    }

    @Deactivate
    public void stop() {
        removeValve(authPipeline);
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof AuthValveFailureSource)) {
            return false;
        }
        return super.equals(obj);
    }

    @Override
    public int hashCode() {
        return super.hashCode();
    }

    @Override
    public void invoke(Object context, ValveContext valveContext) throws PipelineException {
        AuthValveContext authContext = (AuthValveContext) context;
        HttpServletRequest request = authContext.getRequest();
        String remoteAddress = retrieveRemoteAddress(request);

        if (remoteAddress != null && failureRecorder != null && failureRecorder.isIpCurrentlyBanned(remoteAddress)) {
            if (LOGGER.isInfoEnabled()) {
                LOGGER.info("BFLP: Blocked auth attempt from banned IP {}", sanitize(remoteAddress));
            }
            request.setAttribute(LoginEngineAuthValveImpl.VALVE_RESULT, LoginEngineAuthValveImpl.BAD_PASSWORD);
            return;
        }

        String basicAuthHeader = request.getHeader("Authorization");
        boolean hadBasicHeader = basicAuthHeader != null && basicAuthHeader.startsWith(BASIC_PREFIX);

        valveContext.invokeNext(context);

        Object result = request.getAttribute(LoginEngineAuthValveImpl.VALVE_RESULT);
        if (result != null && (LoginEngineAuthValveImpl.BAD_PASSWORD.equals(result)
                || LoginEngineAuthValveImpl.UNKNOWN_USER.equals(result))) {
            if (remoteAddress == null) {
                return;
            }
            Map<String, String> extras = new HashMap<>();
            extras.put("result", String.valueOf(result));
            String username = request.getParameter("username");
            recordFailure(remoteAddress, getName(), username, request, extras);
            return;
        }

        // HttpBasicAuthValveImpl does not set VALVE_RESULT and disables the login event
        // (triggerLoginEventEnabled(false)). We detect failure by checking whether the auth
        // pipeline left the request authenticated: success installs a non-guest user on the
        // session factory, failure falls through with currentUser null/guest.
        if (hadBasicHeader && remoteAddress != null && !isAuthenticated(authContext)) {
            Map<String, String> extras = new HashMap<>();
            extras.put("authScheme", "basic");
            recordFailure(remoteAddress, BASIC_AUTH_SOURCE, extractBasicUsername(basicAuthHeader), request, extras);
        }
    }

    private void recordFailure(String remoteAddress, String sourceName, String username,
                               HttpServletRequest request, Map<String, String> extras) {
        String userAgent = request.getHeader("User-Agent");
        String requestPath = request.getRequestURI();
        FailureEvent event = FailureEvent.builder()
                .ip(remoteAddress)
                .sourceName(sourceName)
                .jailName(getName())
                .timestampMs(System.currentTimeMillis())
                .username(username)
                .userAgent(userAgent)
                .requestPath(requestPath)
                .extras(extras)
                .build();
        try {
            failureRecorder.recordEvent(event);
        } catch (Exception e) {
            LOGGER.warn("BFLP: failure recorder threw: {}", e.getMessage());
        }
    }

    private static boolean isAuthenticated(AuthValveContext authContext) {
        if (authContext.getSessionFactory() == null) {
            return false;
        }
        JahiaUser user = authContext.getSessionFactory().getCurrentUser();
        return user != null && !JahiaUserManagerService.isGuest(user);
    }

    private static String extractBasicUsername(String authHeader) {
        try {
            String encoded = authHeader.substring(BASIC_PREFIX.length()).trim();
            String decoded = new String(Base64.getDecoder().decode(encoded), StandardCharsets.UTF_8);
            int colon = decoded.indexOf(':');
            if (colon <= 0) {
                return null;
            }
            return decoded.substring(0, colon);
        } catch (IllegalArgumentException e) {
            // malformed Base64 — still a failed attempt, just without a username
            return null;
        }
    }

    private String retrieveRemoteAddress(HttpServletRequest request) {
        String remoteAddr = request.getRemoteAddr();
        if (settingsService == null) {
            return remoteAddr;
        }
        GlobalSettings settings = settingsService.getGlobalSettings();
        if (!settings.isTrustProxyHeader()) {
            return remoteAddr;
        }
        List<String> trustedCidrs = settings.getTrustedProxyCidrs();
        if (trustedCidrs == null || trustedCidrs.isEmpty()) {
            if (emptyTrustedProxyWarningEmitted.compareAndSet(false, true)) {
                LOGGER.warn("BFLP: trustProxyHeader=true but no trustedProxyCidrs configured;"
                        + " ignoring X-Forwarded-For and falling back to socket address. Configure"
                        + " trustedProxyCidrs to enable header-based remote-address resolution.");
            }
            return remoteAddr;
        }
        if (!remoteAddrMatchesTrustedProxy(remoteAddr, trustedCidrs)) {
            return remoteAddr;
        }
        String headerValue = request.getHeader(REMOTE_ADDRESS_HEADER);
        if (StringUtils.isNotBlank(headerValue)) {
            String[] parts = headerValue.split(KEY_SEPARATOR);
            String first = parts[0].trim();
            if (!first.isEmpty()) {
                return first;
            }
        }
        return remoteAddr;
    }

    private static boolean remoteAddrMatchesTrustedProxy(String remoteAddr, List<String> cidrs) {
        if (remoteAddr == null) {
            return false;
        }
        for (String cidr : cidrs) {
            String trimmed = StringUtils.trimToNull(cidr);
            if (trimmed == null) {
                continue;
            }
            try {
                if (new CidrMatcher(trimmed).matches(remoteAddr)) {
                    return true;
                }
            } catch (IllegalArgumentException ignored) {
                // skip invalid CIDR
            }
        }
        return false;
    }

    private static String sanitize(String value) {
        return value == null ? null : value.replaceAll("[\r\n]", "");
    }
}
