package org.jahia.community.bruteforceloginprotection.sources;

import org.jahia.community.bruteforceloginprotection.core.BlocklistService;
import org.jahia.community.bruteforceloginprotection.core.GlobalSettings;
import org.jahia.community.bruteforceloginprotection.core.SettingsService;
import org.jahia.community.bruteforceloginprotection.spi.FailureRecorder;
import org.jahia.params.valves.AuthValveContext;
import org.jahia.params.valves.LoginEngineAuthValveImpl;
import org.jahia.pipelines.PipelineException;
import org.jahia.pipelines.valves.ValveContext;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.servlet.http.HttpServletRequest;

import java.lang.reflect.Field;
import java.util.Collections;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the blocklist short-circuit in {@link AuthValveFailureSource#invoke}:
 * a blocklisted IP must be rejected before any downstream valve runs, and a non-blocked
 * IP must proceed through the chain untouched.
 */
@RunWith(MockitoJUnitRunner.class)
public class AuthValveBlocklistTest {

    @Mock
    private FailureRecorder failureRecorder;

    @Mock
    private SettingsService settingsService;

    @Mock
    private BlocklistService blocklistService;

    @Mock
    private HttpServletRequest request;

    @Mock
    private AuthValveContext authContext;

    @Mock
    private ValveContext valveContext;

    private AuthValveFailureSource valve;

    @Before
    public void setUp() throws Exception {
        valve = new AuthValveFailureSource();
        inject("failureRecorder", failureRecorder);
        inject("settingsService", settingsService);
        inject("blocklistService", blocklistService);

        lenient().when(authContext.getRequest()).thenReturn(request);
        lenient().when(request.getRemoteAddr()).thenReturn("203.0.113.42");
        lenient().when(settingsService.getGlobalSettings()).thenReturn(GlobalSettings.builder()
                .activated(true)
                .whitelistIps("")
                .ignorePatterns(Collections.emptyList())
                .build());
        lenient().when(failureRecorder.isIpCurrentlyBanned("203.0.113.42")).thenReturn(false);
    }

    private void inject(String field, Object value) throws Exception {
        Field f = AuthValveFailureSource.class.getDeclaredField(field);
        f.setAccessible(true);
        f.set(valve, value);
    }

    @Test
    public void blocklistedIp_shortCircuits_withoutInvokingChain() throws PipelineException {
        when(blocklistService.getBlockReason("203.0.113.42")).thenReturn(BlocklistService.REASON_STATIC);

        valve.invoke(authContext, valveContext);

        verify(request).setAttribute(LoginEngineAuthValveImpl.VALVE_RESULT, LoginEngineAuthValveImpl.BAD_PASSWORD);
        verify(blocklistService).onBlocked("203.0.113.42", BlocklistService.REASON_STATIC);
        verify(valveContext, never()).invokeNext(any());
    }

    @Test
    public void nonBlockedIp_proceedsThroughChain() throws PipelineException {
        when(blocklistService.getBlockReason("203.0.113.42")).thenReturn(null);

        valve.invoke(authContext, valveContext);

        verify(valveContext).invokeNext(authContext);
        verify(request, never()).setAttribute(LoginEngineAuthValveImpl.VALVE_RESULT, LoginEngineAuthValveImpl.BAD_PASSWORD);
        verify(blocklistService, never()).onBlocked(any(), any());
    }

    @Test
    public void bannedIp_stillShortCircuits_beforeBlocklistIsConsulted() throws PipelineException {
        when(failureRecorder.isIpCurrentlyBanned("203.0.113.42")).thenReturn(true);

        valve.invoke(authContext, valveContext);

        verify(request).setAttribute(LoginEngineAuthValveImpl.VALVE_RESULT, LoginEngineAuthValveImpl.BAD_PASSWORD);
        verify(valveContext, never()).invokeNext(any());
        verify(blocklistService, never()).getBlockReason(any());
    }

    // -------------------------------------------------------------------------------------------
    // F19 residual — retrieveRemoteAddress() falls back to the raw socket address (rather than
    // trusting the X-Forwarded-For header) when trustProxyHeader=true but trustedProxyCidrs is
    // empty, since no proxy hop can be verified as trusted.
    // -------------------------------------------------------------------------------------------

    @Test
    public void retrieveRemoteAddress_fallsBackToSocketAddress_whenTrustedProxyCidrsEmpty() throws PipelineException {
        when(settingsService.getGlobalSettings()).thenReturn(GlobalSettings.builder()
                .activated(true)
                .whitelistIps("")
                .ignorePatterns(Collections.emptyList())
                .trustProxyHeader(true)
                .trustedProxyCidrs(Collections.emptyList())
                .build());
        // Deliberately never consumed: an empty trustedProxyCidrs means the header is never even
        // read (see retrieveRemoteAddress()'s early-return) -- this stub is the negative proof.
        lenient().when(request.getHeader("x-forwarded-for")).thenReturn("6.6.6.6");

        valve.invoke(authContext, valveContext);

        // Must have consulted the ban check with the RAW socket address, not the spoofable header.
        verify(failureRecorder).isIpCurrentlyBanned("203.0.113.42");
        verify(failureRecorder, never()).isIpCurrentlyBanned("6.6.6.6");
    }
}
