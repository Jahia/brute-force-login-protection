package org.jahia.community.bruteforceloginprotection.core;

import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.core.IMap;
import org.jahia.community.bruteforceloginprotection.hazelcast.HazelcastInstanceManager;
import org.jahia.services.content.JCRCallback;
import org.jahia.services.content.JCRSessionWrapper;
import org.jahia.services.content.JCRTemplate;
import org.junit.Before;
import org.junit.Test;

import java.lang.reflect.Field;

import static org.assertj.core.api.Assertions.assertThat;
import static org.jahia.community.bruteforceloginprotection.BruteForceLoginProtectionConstants.BANS_NODE_NAME;
import static org.jahia.community.bruteforceloginprotection.BruteForceLoginProtectionConstants.BANS_NODE_PATH;
import static org.jahia.community.bruteforceloginprotection.BruteForceLoginProtectionConstants.MAP_BANS;
import static org.jahia.community.bruteforceloginprotection.BruteForceLoginProtectionConstants.MAP_NOTIFICATION_MARKERS;
import static org.jahia.community.bruteforceloginprotection.BruteForceLoginProtectionConstants.MAP_WINDOWS;
import static org.jahia.community.bruteforceloginprotection.BruteForceLoginProtectionConstants.NT_BAN;
import static org.jahia.community.bruteforceloginprotection.BruteForceLoginProtectionConstants.NT_BANS_CONTAINER;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * U1 — {@code flush} GraphQL mutation backing logic: {@link BruteForceTracker#flushAll()} clears
 * all 3 Hazelcast maps (bans, windows, notification markers) AND the JCR ban mirror, in one call.
 */
@SuppressWarnings("unchecked")
public class BruteForceTrackerFlushTest {

    private BruteForceTracker tracker;
    private HazelcastInstance hazelcast;
    private IMap<String, BannedIp> bansMap;
    private IMap<String, FailureWindow> windowsMap;
    private IMap<String, Long> notifMarkersMap;
    private JCRSessionWrapper session;
    private FakeJcrNode bansContainer;

    @Before
    public void setUp() throws Exception {
        tracker = new BruteForceTracker();
        HazelcastInstanceManager hazelcastManager = mock(HazelcastInstanceManager.class);
        hazelcast = mock(HazelcastInstance.class);
        JCRTemplate jcrTemplate = mock(JCRTemplate.class);

        bansMap = mock(IMap.class);
        windowsMap = mock(IMap.class);
        notifMarkersMap = mock(IMap.class);
        when(hazelcastManager.getHazelcastInstance()).thenReturn(hazelcast);
        when(hazelcast.<String, BannedIp>getMap(MAP_BANS)).thenReturn(bansMap);
        when(hazelcast.<String, FailureWindow>getMap(MAP_WINDOWS)).thenReturn(windowsMap);
        when(hazelcast.<String, Long>getMap(MAP_NOTIFICATION_MARKERS)).thenReturn(notifMarkersMap);

        session = mock(JCRSessionWrapper.class);
        bansContainer = FakeJcrNode.newRoot(BANS_NODE_NAME, NT_BANS_CONTAINER);
        bansContainer.bindSession(session);
        when(session.nodeExists(BANS_NODE_PATH)).thenReturn(true);
        when(session.getNode(BANS_NODE_PATH)).thenReturn(bansContainer.asMock());
        when(jcrTemplate.doExecuteWithSystemSessionAsUser(any(), anyString(), any(), any(JCRCallback.class)))
                .thenAnswer(inv -> {
                    JCRCallback<?> cb = inv.getArgument(3);
                    return cb.doInJCR(session);
                });

        inject("hazelcastManager", hazelcastManager);
        inject("jcrTemplate", jcrTemplate);
    }

    private void inject(String field, Object value) throws Exception {
        Field f = BruteForceTracker.class.getDeclaredField(field);
        f.setAccessible(true);
        f.set(tracker, value);
    }

    @Test
    public void flushAllClearsAllThreeHazelcastMapsAndJcrBanMirror() throws Exception {
        bansContainer.asMock().addNode("b-1_2_3_4", NT_BAN);
        bansContainer.asMock().addNode("b-5_6_7_8", NT_BAN);
        assertThat(bansContainer.childCount()).isEqualTo(2);

        boolean result = tracker.flushAll();

        assertThat(result).isTrue();
        verify(bansMap).clear();
        verify(windowsMap).clear();
        verify(notifMarkersMap).clear();
        assertThat(bansContainer.childCount()).isZero();
    }

    @Test
    public void flushAllSkipsHazelcastMapClearingWhenInstanceAbsent() throws Exception {
        HazelcastInstanceManager absentManager = mock(HazelcastInstanceManager.class);
        when(absentManager.getHazelcastInstance()).thenReturn(null);
        inject("hazelcastManager", absentManager);

        boolean result = tracker.flushAll();

        assertThat(result).isTrue();
        verify(bansMap, org.mockito.Mockito.never()).clear();
    }
}
