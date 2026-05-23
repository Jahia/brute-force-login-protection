package org.jahia.modules.bruteforceloginprotection.sources;

import org.apache.commons.lang.StringUtils;
import org.jahia.modules.bruteforceloginprotection.BruteForceLoginProtectionConstants;
import org.jahia.modules.bruteforceloginprotection.CidrMatcher;
import org.jahia.modules.bruteforceloginprotection.core.GlobalSettings;
import org.jahia.modules.bruteforceloginprotection.core.SettingsService;
import org.jahia.modules.bruteforceloginprotection.spi.AuthFailureContext;
import org.jahia.modules.bruteforceloginprotection.spi.AuthFailureDetector;
import org.jahia.modules.bruteforceloginprotection.spi.FailureEvent;
import org.jahia.modules.bruteforceloginprotection.spi.FailureRecorder;
import org.jahia.modules.bruteforceloginprotection.spi.FailureSignal;
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
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;

@Component(service = {}, immediate = true)
public final class AuthValveFailureSource extends BaseAuthValve implements FailureSource {

    private static final long serialVersionUID = 1L;
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthValveFailureSource.class);
    private static final String REMOTE_ADDRESS_HEADER = "x-forwarded-for";
    private static final String KEY_SEPARATOR = ",";
    public static final String AUTH_VALVE_ID = "bruteForceLoginProtectionAuthValve";

    private final AtomicBoolean emptyTrustedProxyWarningEmitted = new AtomicBoolean(false);
    private final List<AuthFailureDetector> detectors = new CopyOnWriteArrayList<>();

    @Reference(target = "(type=authentication)")
    private Pipeline authPipeline;

    @Reference
    private FailureRecorder failureRecorder;

    @Reference
    private SettingsService settingsService;

    public AuthValveFailureSource() {
        super();
    }

    @Reference(service = AuthFailureDetector.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC)
    public void bindDetector(AuthFailureDetector detector) {
        detectors.add(detector);
    }

    public void unbindDetector(AuthFailureDetector detector) {
        detectors.remove(detector);
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

        valveContext.invokeNext(context);

        if (remoteAddress == null) {
            return;
        }

        AuthFailureContext detectionContext = new AuthFailureContext(
                request, authContext, isAuthenticated(authContext), remoteAddress);

        FailureSignal signal = runDetectors(detectionContext);
        if (signal != null) {
            recordFailure(remoteAddress, signal, request);
        }
    }

    private FailureSignal runDetectors(AuthFailureContext detectionContext) {
        List<AuthFailureDetector> ordered = new ArrayList<>(detectors);
        ordered.sort(Comparator.comparingInt(AuthFailureDetector::order));
        for (AuthFailureDetector detector : ordered) {
            try {
                FailureSignal signal = detector.detect(detectionContext);
                if (signal != null) {
                    return signal;
                }
            } catch (RuntimeException e) {
                LOGGER.warn("BFLP: detector {} threw: {}",
                        detector.getClass().getName(), e.getMessage());
            }
        }
        return null;
    }

    private void recordFailure(String remoteAddress, FailureSignal signal, HttpServletRequest request) {
        FailureEvent event = FailureEvent.builder()
                .ip(remoteAddress)
                .sourceName(signal.getSourceName())
                .jailName(getName())
                .timestampMs(System.currentTimeMillis())
                .username(signal.getUsername())
                .userAgent(request.getHeader("User-Agent"))
                .requestPath(request.getRequestURI())
                .extras(signal.getExtras())
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

    /** Visible for testing. */
    List<AuthFailureDetector> getDetectorsSnapshot() {
        return Collections.unmodifiableList(new ArrayList<>(detectors));
    }

    private static String sanitize(String value) {
        return value == null ? null : value.replaceAll("[\r\n]", "");
    }
}
