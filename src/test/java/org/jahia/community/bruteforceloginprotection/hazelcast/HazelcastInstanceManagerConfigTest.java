package org.jahia.community.bruteforceloginprotection.hazelcast;

import org.apache.karaf.cellar.core.discovery.DiscoveryService;
import org.junit.Test;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * F8-a / U9 — {@link HazelcastInstanceManager}'s bind-port derivation and bind-address
 * defaulting, extracted into package-private static methods so they are directly unit-testable.
 * U8 — Cellar {@link DiscoveryService} member seeding / port-increment via {@code getCurrentMembers()}.
 */
public class HazelcastInstanceManagerConfigTest {

    // -------------------------------------------------------------------------------------------
    // F8-a — bind-port +2 offset derivation
    // -------------------------------------------------------------------------------------------

    @Test
    public void derivedBindPortAppliesPlusTwoOffsetWhenBasePortValid() {
        assertThat(HazelcastInstanceManager.derivedBindPortProperty("7860", null)).isEqualTo("7862");
    }

    @Test
    public void derivedBindPortFallsBackToDefaultWhenBasePortInvalid() {
        assertThat(HazelcastInstanceManager.derivedBindPortProperty("not-a-number", null))
                .isEqualTo(HazelcastInstanceManager.DEFAULT_BIND_PORT);
    }

    @Test
    public void derivedBindPortFallsBackToDefaultWhenNothingSet() {
        assertThat(HazelcastInstanceManager.derivedBindPortProperty(null, null))
                .isEqualTo(HazelcastInstanceManager.DEFAULT_BIND_PORT);
    }

    @Test
    public void derivedBindPortKeepsExistingValueWhenNoBasePortButAlreadySet() {
        assertThat(HazelcastInstanceManager.derivedBindPortProperty(null, "9999")).isEqualTo("9999");
    }

    // -------------------------------------------------------------------------------------------
    // U9 — cluster.tcp.bindAddress defaults to loopback unless already set
    // -------------------------------------------------------------------------------------------

    @Test
    public void derivedBindAddressDefaultsToLoopbackWhenUnset() {
        assertThat(HazelcastInstanceManager.derivedBindAddress(null))
                .isEqualTo(HazelcastInstanceManager.DEFAULT_BIND_ADDRESS);
        assertThat(HazelcastInstanceManager.derivedBindAddress(""))
                .isEqualTo(HazelcastInstanceManager.DEFAULT_BIND_ADDRESS);
    }

    @Test
    public void derivedBindAddressKeepsExplicitlySetValue() {
        assertThat(HazelcastInstanceManager.derivedBindAddress("192.168.1.50")).isEqualTo("192.168.1.50");
    }

    // -------------------------------------------------------------------------------------------
    // U8 — Cellar DiscoveryService member seeding + port+2 increment
    // -------------------------------------------------------------------------------------------

    @SuppressWarnings("unchecked")
    private static Set<String> invokeGetCurrentMembers(HazelcastInstanceManager manager) throws Exception {
        Method m = HazelcastInstanceManager.class.getDeclaredMethod("getCurrentMembers");
        m.setAccessible(true);
        return (Set<String>) m.invoke(manager);
    }

    @Test
    public void getCurrentMembersAggregatesAndIncrementsPortByTwo() throws Exception {
        HazelcastInstanceManager manager = new HazelcastInstanceManager();
        DiscoveryService discovery = mock(DiscoveryService.class);
        when(discovery.discoverMembers()).thenReturn(new HashSet<>(java.util.Arrays.asList("10.0.0.1:5701")));
        manager.addDiscoveryService(discovery);

        Set<String> members = invokeGetCurrentMembers(manager);

        assertThat(members).containsExactly("10.0.0.1:5703");
    }

    @Test
    public void getCurrentMembersAggregatesMultipleDiscoveryServices() throws Exception {
        HazelcastInstanceManager manager = new HazelcastInstanceManager();
        DiscoveryService d1 = mock(DiscoveryService.class);
        when(d1.discoverMembers()).thenReturn(Collections.singleton("10.0.0.1:5701"));
        DiscoveryService d2 = mock(DiscoveryService.class);
        when(d2.discoverMembers()).thenReturn(Collections.singleton("10.0.0.2:5701"));
        manager.addDiscoveryService(d1);
        manager.addDiscoveryService(d2);

        Set<String> members = invokeGetCurrentMembers(manager);

        assertThat(members).containsExactlyInAnyOrder("10.0.0.1:5703", "10.0.0.2:5703");
    }

    @Test
    public void getCurrentMembersSkipsDiscoveryServiceThatThrows() throws Exception {
        HazelcastInstanceManager manager = new HazelcastInstanceManager();
        DiscoveryService throwing = mock(DiscoveryService.class);
        when(throwing.discoverMembers()).thenThrow(new RuntimeException("boom"));
        DiscoveryService good = mock(DiscoveryService.class);
        when(good.discoverMembers()).thenReturn(Collections.singleton("10.0.0.3:5701"));
        manager.addDiscoveryService(throwing);
        manager.addDiscoveryService(good);

        Set<String> members = invokeGetCurrentMembers(manager);

        assertThat(members).containsExactly("10.0.0.3:5703");
    }

    @Test
    public void getCurrentMembersReturnsEmptySetWhenNoDiscoveryServices() throws Exception {
        HazelcastInstanceManager manager = new HazelcastInstanceManager();
        assertThat(invokeGetCurrentMembers(manager)).isEmpty();
    }

    @Test
    public void removeDiscoveryServiceStopsItFromBeingConsulted() throws Exception {
        HazelcastInstanceManager manager = new HazelcastInstanceManager();
        DiscoveryService discovery = mock(DiscoveryService.class);
        when(discovery.discoverMembers()).thenReturn(Collections.singleton("10.0.0.1:5701"));
        manager.addDiscoveryService(discovery);
        manager.removeDiscoveryService(discovery);

        assertThat(invokeGetCurrentMembers(manager)).isEmpty();
    }

    // -------------------------------------------------------------------------------------------
    // U8 — run()'s changed-vs-unchanged no-op guard, and the not-running guard.
    // -------------------------------------------------------------------------------------------

    @SuppressWarnings("unchecked")
    private static void injectHazelcastInstance(HazelcastInstanceManager manager, com.hazelcast.core.HazelcastInstance hz) throws Exception {
        Field f = HazelcastInstanceManager.class.getDeclaredField("hazelcastInstance");
        f.setAccessible(true);
        ((java.util.concurrent.atomic.AtomicReference<com.hazelcast.core.HazelcastInstance>) f.get(manager)).set(hz);
    }

    @Test
    public void runIsNoOpWhenHazelcastInstanceIsNull() throws Exception {
        HazelcastInstanceManager manager = new HazelcastInstanceManager();
        // hazelcastInstance is null by default (no @Activate called in this unit test) -- run()
        // must return immediately without throwing.
        manager.run();
    }

    @Test
    public void runIsNoOpWhenHazelcastInstanceIsNotRunning() throws Exception {
        HazelcastInstanceManager manager = new HazelcastInstanceManager();
        com.hazelcast.core.HazelcastInstance hz = mock(com.hazelcast.core.HazelcastInstance.class);
        com.hazelcast.core.LifecycleService lifecycle = mock(com.hazelcast.core.LifecycleService.class);
        when(hz.getLifecycleService()).thenReturn(lifecycle);
        when(lifecycle.isRunning()).thenReturn(false);
        injectHazelcastInstance(manager, hz);

        manager.run();

        org.mockito.Mockito.verify(hz, org.mockito.Mockito.never()).getConfig();
    }
}
