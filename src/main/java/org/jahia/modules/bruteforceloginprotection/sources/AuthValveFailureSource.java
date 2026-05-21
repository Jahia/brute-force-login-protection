package org.jahia.modules.bruteforceloginprotection.sources;

import org.apache.commons.lang.StringUtils;
import org.jahia.modules.bruteforceloginprotection.BruteForceLoginProtectionConstants;
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
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;

@Component(service = {}, immediate = true)
public final class AuthValveFailureSource extends BaseAuthValve implements FailureSource {

    private static final long serialVersionUID = 1L;
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthValveFailureSource.class);
    private static final String REMOTE_ADDRESS_HEADER = "x-forwarded-for";
    private static final String KEY_SEPARATOR = ",";
    public static final String AUTH_VALVE_ID = "bruteForceLoginProtectionAuthValve";

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
            LOGGER.info("BFLP: Blocked auth attempt from banned IP {}", sanitize(remoteAddress));
            request.setAttribute(LoginEngineAuthValveImpl.VALVE_RESULT, LoginEngineAuthValveImpl.BAD_PASSWORD);
            return;
        }

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
            String userAgent = request.getHeader("User-Agent");
            String requestPath = request.getRequestURI();
            FailureEvent event = new FailureEvent(remoteAddress, getName(), getName(),
                    System.currentTimeMillis(), username, userAgent, requestPath, extras);
            try {
                failureRecorder.record(event);
            } catch (Exception e) {
                LOGGER.warn("BFLP: failure recorder threw: {}", e.getMessage());
            }
        }
    }

    private String retrieveRemoteAddress(HttpServletRequest request) {
        if (settingsService != null && settingsService.getGlobalSettings().isTrustProxyHeader()) {
            String headerValue = request.getHeader(REMOTE_ADDRESS_HEADER);
            if (StringUtils.isNotBlank(headerValue)) {
                String[] parts = headerValue.split(KEY_SEPARATOR);
                String first = parts[0].trim();
                if (!first.isEmpty()) {
                    return first;
                }
            }
        }
        return request.getRemoteAddr();
    }

    private static String sanitize(String value) {
        return value == null ? null : value.replaceAll("[\r\n]", "");
    }
}
