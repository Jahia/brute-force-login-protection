package org.jahia.community.bruteforceloginprotection.hazelcast;

import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.core.LifecycleService;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.osgi.framework.BundleContext;

import java.lang.reflect.Field;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the deactivation path of {@link HazelcastInstanceManager}.
 *
 * The module MUST terminate (not gracefully shut down) its Hazelcast instance on bundle stop:
 * graceful shutdown blocks until all partition replicas owned by the leaving member have been
 * migrated, which can stall indefinitely (observed in production during module updates) and
 * hangs the whole OSGi bundle refresh. All module state in Hazelcast is reconstructible —
 * bans from the JCR mirror, windows are transient — so skipping replica migration is safe
 * (see ADR 0005).
 */
@RunWith(MockitoJUnitRunner.class)
public class HazelcastInstanceManagerShutdownTest {

    @Mock
    private HazelcastInstance hz;

    @Mock
    private LifecycleService lifecycleService;

    @Mock
    private BundleContext bundleContext;

    @SuppressWarnings("unchecked")
    private static void injectInstance(HazelcastInstanceManager manager, HazelcastInstance hz) throws Exception {
        Field f = HazelcastInstanceManager.class.getDeclaredField("hazelcastInstance");
        f.setAccessible(true);
        ((AtomicReference<HazelcastInstance>) f.get(manager)).set(hz);
    }

    @Test
    public void destroy_terminatesInsteadOfGracefulShutdown() throws Exception {
        HazelcastInstanceManager manager = new HazelcastInstanceManager();
        injectInstance(manager, hz);
        when(hz.getLifecycleService()).thenReturn(lifecycleService);

        manager.destroy(bundleContext);

        verify(lifecycleService).terminate();
        verify(hz, never()).shutdown();
        assertThat(manager.getHazelcastInstance()).isNull();
    }

    @Test
    public void destroy_withoutInstance_doesNotThrow() {
        HazelcastInstanceManager manager = new HazelcastInstanceManager();
        assertThatCode(() -> manager.destroy(bundleContext)).doesNotThrowAnyException();
    }

    @Test
    public void destroy_terminateFailure_isSwallowed() throws Exception {
        HazelcastInstanceManager manager = new HazelcastInstanceManager();
        injectInstance(manager, hz);
        when(hz.getLifecycleService()).thenThrow(new IllegalStateException("already down"));

        assertThatCode(() -> manager.destroy(bundleContext)).doesNotThrowAnyException();
        assertThat(manager.getHazelcastInstance()).isNull();
    }
}
