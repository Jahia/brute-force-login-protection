package org.jahia.community.bruteforceloginprotection.sources;

import org.jahia.community.bruteforceloginprotection.core.GlobalSettings;
import org.jahia.community.bruteforceloginprotection.core.SettingsService;
import org.jahia.community.bruteforceloginprotection.detectors.ApiTokenAuthFailureDetector;
import org.jahia.community.bruteforceloginprotection.detectors.BasicAuthFailureDetector;
import org.jahia.community.bruteforceloginprotection.detectors.FormLoginFailureDetector;
import org.jahia.community.bruteforceloginprotection.detectors.JahiaTokenAuthFailureDetector;
import org.jahia.community.bruteforceloginprotection.spi.AuthFailureDetector;
import org.jahia.community.bruteforceloginprotection.spi.FailureRecorder;
import org.jahia.community.bruteforceloginprotection.spi.FailureSignal;
import org.jahia.params.valves.AuthValveContext;
import org.jahia.params.valves.LoginEngineAuthValveImpl;
import org.jahia.pipelines.PipelineException;
import org.jahia.pipelines.valves.ValveContext;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import javax.servlet.http.HttpServletRequest;
import java.lang.reflect.Field;
import java.util.Base64;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * F4/F5 — {@link AuthValveFailureSource}'s detector-chain dispatch: registered
 * {@link AuthFailureDetector}s run in ascending {@code order()}, the first non-null
 * {@link FailureSignal} wins, a throwing detector is swallowed (and does not block the next
 * detector), and at most one {@link org.jahia.community.bruteforceloginprotection.spi.FailureEvent}
 * is ever recorded per request.
 */
@RunWith(MockitoJUnitRunner.class)
public class AuthValveDetectorDispatchTest {

    @Mock
    private FailureRecorder failureRecorder;

    @Mock
    private SettingsService settingsService;

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

        lenient().when(authContext.getRequest()).thenReturn(request);
        lenient().when(request.getRemoteAddr()).thenReturn("203.0.113.42");
        lenient().when(settingsService.getGlobalSettings()).thenReturn(GlobalSettings.builder()
                .activated(true)
                .whitelistIps("")
                .ignorePatterns(Collections.emptyList())
                .ignorePaths(Collections.emptyList())
                .build());
        lenient().when(failureRecorder.isIpCurrentlyBanned(any())).thenReturn(false);
    }

    private void inject(String field, Object value) throws Exception {
        Field f = AuthValveFailureSource.class.getDeclaredField(field);
        f.setAccessible(true);
        f.set(valve, value);
    }

    private static AuthFailureDetector mockDetector(int order, FailureSignal signal) {
        AuthFailureDetector d = mock(AuthFailureDetector.class);
        when(d.order()).thenReturn(order);
        when(d.detect(any())).thenReturn(signal);
        return d;
    }

    // -------------------------------------------------------------------------------------------
    // F4 — ordered dispatch, first-non-null-signal-wins, exception-swallowing
    // -------------------------------------------------------------------------------------------

    @Test
    public void onlyLowestOrderDetectorSignalIsRecorded() throws PipelineException {
        FailureSignal low = FailureSignal.builder("low-order").username("alice").build();
        FailureSignal high = FailureSignal.builder("high-order").username("bob").build();
        valve.bindDetector(mockDetector(100, high));
        valve.bindDetector(mockDetector(50, low));

        valve.invoke(authContext, valveContext);

        ArgumentCaptor<org.jahia.community.bruteforceloginprotection.spi.FailureEvent> captor =
                ArgumentCaptor.forClass(org.jahia.community.bruteforceloginprotection.spi.FailureEvent.class);
        verify(failureRecorder).recordEvent(captor.capture());
        assertThat(captor.getValue().getSourceName()).isEqualTo("low-order");
        assertThat(captor.getValue().getUsername()).isEqualTo("alice");
    }

    @Test
    public void throwingDetectorIsSwallowedAndDoesNotBlockNextDetector() throws PipelineException {
        AuthFailureDetector throwing = mock(AuthFailureDetector.class);
        when(throwing.order()).thenReturn(10);
        when(throwing.detect(any())).thenThrow(new RuntimeException("boom"));
        FailureSignal signal = FailureSignal.builder("next-detector").build();
        valve.bindDetector(throwing);
        valve.bindDetector(mockDetector(20, signal));

        valve.invoke(authContext, valveContext);

        ArgumentCaptor<org.jahia.community.bruteforceloginprotection.spi.FailureEvent> captor =
                ArgumentCaptor.forClass(org.jahia.community.bruteforceloginprotection.spi.FailureEvent.class);
        verify(failureRecorder).recordEvent(captor.capture());
        assertThat(captor.getValue().getSourceName()).isEqualTo("next-detector");
    }

    @Test
    public void unbindDetectorRemovesItFromDispatch() throws PipelineException {
        AuthFailureDetector d = mockDetector(50, FailureSignal.builder("unbound").build());
        valve.bindDetector(d);
        valve.unbindDetector(d);

        valve.invoke(authContext, valveContext);

        verify(failureRecorder, org.mockito.Mockito.never()).recordEvent(any());
    }

    // -------------------------------------------------------------------------------------------
    // F5 — real built-in detectors wired together: single event per request, dispatch-priority
    // ordering, and no username leak on bearer-token paths.
    // -------------------------------------------------------------------------------------------

    @Test
    public void realDetectorChainRecordsAtMostOneEventAndFormLoginWinsOverBasicAuth() throws PipelineException {
        valve.bindDetector(new FormLoginFailureDetector());
        valve.bindDetector(new BasicAuthFailureDetector());
        valve.bindDetector(new ApiTokenAuthFailureDetector());
        valve.bindDetector(new JahiaTokenAuthFailureDetector());

        // Request could match BOTH form-login (VALVE_RESULT) and Basic auth (header present).
        when(request.getAttribute(LoginEngineAuthValveImpl.VALVE_RESULT))
                .thenReturn(LoginEngineAuthValveImpl.BAD_PASSWORD);
        when(request.getParameter("username")).thenReturn("alice");
        String basicHeader = "Basic " + Base64.getEncoder().encodeToString("root:badpass".getBytes());
        // FormLoginFailureDetector wins (lower order), so this stub is deliberately never consumed
        // -- it's the proof that BasicAuthFailureDetector.detect() never even runs.
        lenient().when(request.getHeader("Authorization")).thenReturn(basicHeader);

        valve.invoke(authContext, valveContext);

        ArgumentCaptor<org.jahia.community.bruteforceloginprotection.spi.FailureEvent> captor =
                ArgumentCaptor.forClass(org.jahia.community.bruteforceloginprotection.spi.FailureEvent.class);
        verify(failureRecorder, org.mockito.Mockito.times(1)).recordEvent(captor.capture());
        // FormLoginFailureDetector (order 100) wins over BasicAuthFailureDetector (order 200).
        assertThat(captor.getValue().getSourceName()).isEqualTo("login");
    }

    @Test
    public void bearerTokenDetectorChainNeverLeaksUsername() throws PipelineException {
        valve.bindDetector(new FormLoginFailureDetector());
        valve.bindDetector(new BasicAuthFailureDetector());
        valve.bindDetector(new ApiTokenAuthFailureDetector());
        valve.bindDetector(new JahiaTokenAuthFailureDetector());

        when(request.getHeader("Authorization")).thenReturn("APIToken secret-bearer-xxxxxxxxxxxxxxxx");

        valve.invoke(authContext, valveContext);

        ArgumentCaptor<org.jahia.community.bruteforceloginprotection.spi.FailureEvent> captor =
                ArgumentCaptor.forClass(org.jahia.community.bruteforceloginprotection.spi.FailureEvent.class);
        verify(failureRecorder, org.mockito.Mockito.times(1)).recordEvent(captor.capture());
        assertThat(captor.getValue().getSourceName()).isEqualTo("api-token-valve");
        assertThat(captor.getValue().getUsername()).isNull();
    }
}
