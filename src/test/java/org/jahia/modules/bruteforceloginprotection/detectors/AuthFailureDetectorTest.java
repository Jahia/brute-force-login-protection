package org.jahia.modules.bruteforceloginprotection.detectors;

import org.jahia.modules.bruteforceloginprotection.spi.AuthFailureContext;
import org.jahia.modules.bruteforceloginprotection.spi.FailureSignal;
import org.jahia.params.valves.AuthValveContext;
import org.jahia.params.valves.LoginEngineAuthValveImpl;
import org.junit.Test;

import javax.servlet.http.HttpServletRequest;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class AuthFailureDetectorTest {

    @Test
    public void formLoginDetectorMatchesValveResult() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getAttribute(LoginEngineAuthValveImpl.VALVE_RESULT))
                .thenReturn(LoginEngineAuthValveImpl.BAD_PASSWORD);
        when(request.getParameter("username")).thenReturn("alice");

        FailureSignal signal = new FormLoginFailureDetector().detect(
                new AuthFailureContext(request, mock(AuthValveContext.class), false, "1.2.3.4"));

        assertThat(signal).isNotNull();
        assertThat(signal.getSourceName()).isEqualTo("login");
        assertThat(signal.getUsername()).isEqualTo("alice");
        assertThat(signal.getExtras()).containsEntry("result", LoginEngineAuthValveImpl.BAD_PASSWORD);
    }

    @Test
    public void formLoginDetectorIgnoresUnsetValveResult() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        FailureSignal signal = new FormLoginFailureDetector().detect(
                new AuthFailureContext(request, mock(AuthValveContext.class), false, "1.2.3.4"));
        assertThat(signal).isNull();
    }

    @Test
    public void basicAuthDetectorMatchesPrefixAndExtractsUsername() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        String header = "Basic " + Base64.getEncoder().encodeToString("root:badpass".getBytes());
        when(request.getHeader("Authorization")).thenReturn(header);

        FailureSignal signal = new BasicAuthFailureDetector().detect(
                new AuthFailureContext(request, mock(AuthValveContext.class), false, "1.2.3.4"));

        assertThat(signal).isNotNull();
        assertThat(signal.getSourceName()).isEqualTo("basic-auth-valve");
        assertThat(signal.getUsername()).isEqualTo("root");
        assertThat(signal.getExtras()).containsEntry("authScheme", "basic");
    }

    @Test
    public void basicAuthDetectorSkipsWhenAuthenticated() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader("Authorization")).thenReturn("Basic anything");
        FailureSignal signal = new BasicAuthFailureDetector().detect(
                new AuthFailureContext(request, mock(AuthValveContext.class), true, "1.2.3.4"));
        assertThat(signal).isNull();
    }

    @Test
    public void basicAuthDetectorIgnoresOtherSchemes() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader("Authorization")).thenReturn("Bearer foo");
        FailureSignal signal = new BasicAuthFailureDetector().detect(
                new AuthFailureContext(request, mock(AuthValveContext.class), false, "1.2.3.4"));
        assertThat(signal).isNull();
    }

    @Test
    public void apiTokenDetectorMatchesAndDoesNotLeakToken() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader("Authorization")).thenReturn("APIToken secret-bearer-xxxxxxxxxxxxxxxx");

        FailureSignal signal = new ApiTokenAuthFailureDetector().detect(
                new AuthFailureContext(request, mock(AuthValveContext.class), false, "1.2.3.4"));

        assertThat(signal).isNotNull();
        assertThat(signal.getSourceName()).isEqualTo("api-token-valve");
        assertThat(signal.getUsername()).isNull();
        assertThat(signal.getExtras()).containsEntry("authScheme", "apitoken");
    }

    @Test
    public void apiTokenDetectorSkipsWhenAuthenticated() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader("Authorization")).thenReturn("APIToken whatever");
        FailureSignal signal = new ApiTokenAuthFailureDetector().detect(
                new AuthFailureContext(request, mock(AuthValveContext.class), true, "1.2.3.4"));
        assertThat(signal).isNull();
    }

    @Test
    public void jahiaTokenDetectorMatchesHeader() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader("jahiatoken")).thenReturn("opaque-token-value");

        FailureSignal signal = new JahiaTokenAuthFailureDetector().detect(
                new AuthFailureContext(request, mock(AuthValveContext.class), false, "1.2.3.4"));

        assertThat(signal).isNotNull();
        assertThat(signal.getSourceName()).isEqualTo("jahia-token-valve");
        assertThat(signal.getUsername()).isNull();
        assertThat(signal.getExtras()).containsEntry("authScheme", "jahiatoken");
    }

    @Test
    public void jahiaTokenDetectorIgnoresMissingHeader() {
        HttpServletRequest request = mock(HttpServletRequest.class);
        FailureSignal signal = new JahiaTokenAuthFailureDetector().detect(
                new AuthFailureContext(request, mock(AuthValveContext.class), false, "1.2.3.4"));
        assertThat(signal).isNull();
    }

    @Test
    public void builtinDetectorOrdersAreUnique() {
        int form = new FormLoginFailureDetector().order();
        int basic = new BasicAuthFailureDetector().order();
        int api = new ApiTokenAuthFailureDetector().order();
        int jahia = new JahiaTokenAuthFailureDetector().order();
        assertThat(form).isLessThan(basic);
        assertThat(basic).isLessThan(api);
        assertThat(api).isLessThan(jahia);
    }
}
