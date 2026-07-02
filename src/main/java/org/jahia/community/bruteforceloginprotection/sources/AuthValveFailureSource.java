package org.jahia.community.bruteforceloginprotection.sources;

import org.apache.commons.lang.StringUtils;
import org.jahia.community.bruteforceloginprotection.BruteForceLoginProtectionConstants;
import org.jahia.community.bruteforceloginprotection.CidrMatcher;
import org.jahia.community.bruteforceloginprotection.core.AuditLogger;
import org.jahia.community.bruteforceloginprotection.core.BlocklistService;
import org.jahia.community.bruteforceloginprotection.core.GlobalSettings;
import org.jahia.community.bruteforceloginprotection.core.SettingsService;
import org.jahia.community.bruteforceloginprotection.spi.AuthFailureContext;
import org.jahia.community.bruteforceloginprotection.spi.AuthFailureDetector;
import org.jahia.community.bruteforceloginprotection.spi.FailureEvent;
import org.jahia.community.bruteforceloginprotection.spi.FailureRecorder;
import org.jahia.community.bruteforceloginprotection.spi.FailureSignal;
import org.jahia.community.bruteforceloginprotection.spi.FailureSource;
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

    @Reference
    private BlocklistService blocklistService;

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
                LOGGER.info("BFLP: Blocked auth attempt from banned IP {}", AuditLogger.sanitize(remoteAddress));
            }
            request.setAttribute(LoginEngineAuthValveImpl.VALVE_RESULT, LoginEngineAuthValveImpl.BAD_PASSWORD);
            return;
        }

        // Proactive blocklist (static CIDRs + Tor exit list). Checked after the ban map so a ban
        // keeps its recidive bookkeeping, but before any downstream auth work. Whitelist
        // precedence is handled inside BlocklistService.
        if (remoteAddress != null && blocklistService != null) {
            String blockReason = blocklistService.getBlockReason(remoteAddress);
            if (blockReason != null) {
                blocklistService.onBlocked(remoteAddress, blockReason);
                request.setAttribute(LoginEngineAuthValveImpl.VALVE_RESULT, LoginEngineAuthValveImpl.BAD_PASSWORD);
                return;
            }
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
        if (!matchesAnyCidr(remoteAddr, trustedCidrs)) {
            return remoteAddr;
        }
        String headerValue = request.getHeader(REMOTE_ADDRESS_HEADER);
        if (StringUtils.isBlank(headerValue)) {
            return remoteAddr;
        }
        String client = extractClientFromForwardedChain(headerValue, trustedCidrs);
        return client != null ? client : remoteAddr;
    }

    /**
     * Resolves the real client address from an {@code X-Forwarded-For} chain, walking
     * <strong>right-to-left</strong> and skipping addresses that belong to a trusted proxy.
     * The first non-trusted, well-formed IP literal encountered is the real client.
     *
     * <p>This is the security-critical parsing rule for a brute-force counter: taking the
     * leftmost entry would let any client spoof its address (proxies <em>append</em> the real
     * peer, so the leftmost value is attacker-controlled), enabling both ban evasion and the
     * wrongful banning of arbitrary victim IPs. We therefore trust only the hops the proxy
     * itself added.</p>
     *
     * <p>Returns {@code null} when no untrusted address can be established (e.g. every entry is
     * a trusted proxy, or a malformed entry breaks the chain), so the caller falls back to the
     * socket peer address.</p>
     *
     * <p>Package-private for unit testing.</p>
     */
    static String extractClientFromForwardedChain(String headerValue, List<String> trustedCidrs) {
        String[] parts = headerValue.split(KEY_SEPARATOR);
        for (int i = parts.length - 1; i >= 0; i--) {
            String candidate = parts[i].trim();
            if (!candidate.isEmpty()) {
                if (!isValidIpLiteral(candidate)) {
                    // A malformed hop means we can no longer trust positions further left, since an
                    // attacker could have injected the garbage; stop and fall back to the socket peer.
                    return null;
                }
                if (!matchesAnyCidr(candidate, trustedCidrs)) {
                    // First non-trusted, well-formed address from the right == the real client.
                    return candidate;
                }
                // Otherwise it's a hop added by a trusted proxy — keep walking towards the client.
            }
        }
        return null;
    }

    private static boolean matchesAnyCidr(String address, List<String> cidrs) {
        if (address == null || cidrs == null) {
            return false;
        }
        for (String cidr : cidrs) {
            String trimmed = StringUtils.trimToNull(cidr);
            if (trimmed == null) {
                continue;
            }
            try {
                if (new CidrMatcher(trimmed).matches(address)) {
                    return true;
                }
            } catch (IllegalArgumentException ignored) {
                // skip invalid CIDR
            }
        }
        return false;
    }

    /**
     * True when {@code value} is a numeric IPv4 or IPv6 literal. Deliberately rejects anything
     * containing letters outside the IPv6 hex set so that an attacker-supplied
     * {@code X-Forwarded-For} value can never (a) trigger a DNS lookup via {@code getByName} or
     * (b) be persisted verbatim as a Hazelcast map key / JCR node name.
     */
    static boolean isValidIpLiteral(String value) {
        // CidrMatcher.isIpLiteral applies the character whitelist that guarantees the subsequent
        // getByName parses a literal without ever performing a DNS lookup.
        if (!CidrMatcher.isIpLiteral(value)) {
            return false;
        }
        try {
            java.net.InetAddress.getByName(value);
            return true;
        } catch (java.net.UnknownHostException e) {
            return false;
        }
    }

    /** Visible for testing. */
    List<AuthFailureDetector> getDetectorsSnapshot() {
        return Collections.unmodifiableList(new ArrayList<>(detectors));
    }
}
