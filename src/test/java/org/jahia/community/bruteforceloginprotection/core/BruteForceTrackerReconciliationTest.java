package org.jahia.community.bruteforceloginprotection.core;

import com.hazelcast.core.IMap;
import org.jahia.services.content.JCRSessionWrapper;
import org.junit.Before;
import org.junit.Test;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.jahia.community.bruteforceloginprotection.BruteForceLoginProtectionConstants.BANS_NODE_NAME;
import static org.jahia.community.bruteforceloginprotection.BruteForceLoginProtectionConstants.NT_BAN;
import static org.jahia.community.bruteforceloginprotection.BruteForceLoginProtectionConstants.NT_BANS_CONTAINER;
import static org.jahia.community.bruteforceloginprotection.BruteForceLoginProtectionConstants.PROP_BAN_AT;
import static org.jahia.community.bruteforceloginprotection.BruteForceLoginProtectionConstants.PROP_BAN_COUNT;
import static org.jahia.community.bruteforceloginprotection.BruteForceLoginProtectionConstants.PROP_BAN_IP;
import static org.jahia.community.bruteforceloginprotection.BruteForceLoginProtectionConstants.PROP_BAN_JAIL;
import static org.jahia.community.bruteforceloginprotection.BruteForceLoginProtectionConstants.PROP_BAN_UNTIL;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * F10 — startup ban reconciliation between the (authoritative) Hazelcast ban map and the
 * best-effort JCR mirror: {@link BruteForceTracker#reconcileBansInSession}.
 *
 * Uses {@link FakeJcrNode} as a lightweight in-memory JCR fixture rather than a live repository.
 */
@SuppressWarnings("unchecked")
public class BruteForceTrackerReconciliationTest {

    private IMap<String, BannedIp> bansMap;
    private java.util.Map<String, BannedIp> bansStore;
    private JCRSessionWrapper session;
    private FakeJcrNode bansContainer;

    @Before
    public void setUp() {
        bansMap = mock(IMap.class);
        bansStore = new ConcurrentHashMap<>();
        when(bansMap.containsKey(anyString())).thenAnswer(inv -> bansStore.containsKey((String) inv.getArgument(0)));
        when(bansMap.putIfAbsent(anyString(), any(BannedIp.class), anyLong(), any(TimeUnit.class)))
                .thenAnswer(inv -> bansStore.putIfAbsent(inv.getArgument(0), inv.getArgument(1)));

        session = mock(JCRSessionWrapper.class);
        bansContainer = FakeJcrNode.newRoot(BANS_NODE_NAME, NT_BANS_CONTAINER);
        bansContainer.bindSession(session);
    }

    private void addBanNode(String nodeName, String ip, String jail, long bannedUntil, int banCount) throws Exception {
        var node = bansContainer.asMock().addNode(nodeName, NT_BAN);
        node.setProperty(PROP_BAN_IP, ip);
        node.setProperty(PROP_BAN_JAIL, jail);
        node.setProperty(PROP_BAN_UNTIL, bannedUntil);
        node.setProperty(PROP_BAN_AT, System.currentTimeMillis());
        node.setProperty(PROP_BAN_COUNT, (long) banCount);
    }

    @Test
    public void staleBanNodeIsRemovedAndNotRestored() throws Exception {
        long now = System.currentTimeMillis();
        addBanNode("b-1_2_3_4", "1.2.3.4", "login", now - 60_000L, 1); // already expired

        when(session.nodeExists("/settings/bruteforceloginprotection/bans")).thenReturn(true);
        when(session.getNode("/settings/bruteforceloginprotection/bans")).thenReturn(bansContainer.asMock());

        BruteForceTracker.reconcileBansInSession(session, bansMap);

        assertThat(bansStore).isEmpty();
        assertThat(bansContainer.childCount()).isZero();
    }

    @Test
    public void liveBanIsRestoredIntoHazelcastMapWithDerivedTtl() throws Exception {
        long now = System.currentTimeMillis();
        long until = now + 120_000L; // 2 minutes in the future
        addBanNode("b-5_6_7_8", "5.6.7.8", "login", until, 2);

        when(session.nodeExists("/settings/bruteforceloginprotection/bans")).thenReturn(true);
        when(session.getNode("/settings/bruteforceloginprotection/bans")).thenReturn(bansContainer.asMock());

        BruteForceTracker.reconcileBansInSession(session, bansMap);

        assertThat(bansStore).containsKey("5.6.7.8");
        BannedIp restored = bansStore.get("5.6.7.8");
        assertThat(restored.getJailName()).isEqualTo("login");
        assertThat(restored.getBanCount()).isEqualTo(2);
        assertThat(restored.getBannedUntil()).isEqualTo(until);
        // Node must NOT be removed for a live ban.
        assertThat(bansContainer.childCount()).isEqualTo(1);
    }

    @Test
    public void liveBanAlreadyPresentInMapIsNotOverwritten() throws Exception {
        long now = System.currentTimeMillis();
        long until = now + 120_000L;
        addBanNode("b-9_9_9_9", "9.9.9.9", "login", until, 1);
        BannedIp existing = new BannedIp("9.9.9.9", "login", "manual", now, until, 99, "already present");
        bansStore.put("9.9.9.9", existing);

        when(session.nodeExists("/settings/bruteforceloginprotection/bans")).thenReturn(true);
        when(session.getNode("/settings/bruteforceloginprotection/bans")).thenReturn(bansContainer.asMock());

        BruteForceTracker.reconcileBansInSession(session, bansMap);

        // putIfAbsent must not clobber the existing in-memory entry.
        assertThat(bansStore.get("9.9.9.9").getBanCount()).isEqualTo(99);
    }

    @Test
    public void noBansContainerIsANoOp() throws Exception {
        when(session.nodeExists("/settings/bruteforceloginprotection/bans")).thenReturn(false);

        BruteForceTracker.reconcileBansInSession(session, bansMap);

        assertThat(bansStore).isEmpty();
    }

    @Test
    public void mixOfStaleAndLiveBansHandledInOneSession() throws Exception {
        long now = System.currentTimeMillis();
        addBanNode("b-1_1_1_1", "1.1.1.1", "login", now - 5_000L, 1); // stale
        addBanNode("b-2_2_2_2", "2.2.2.2", "login", now + 60_000L, 1); // live

        when(session.nodeExists("/settings/bruteforceloginprotection/bans")).thenReturn(true);
        when(session.getNode("/settings/bruteforceloginprotection/bans")).thenReturn(bansContainer.asMock());

        BruteForceTracker.reconcileBansInSession(session, bansMap);

        assertThat(bansStore).containsOnlyKeys("2.2.2.2");
        assertThat(bansContainer.childCount()).isEqualTo(1);
    }
}
