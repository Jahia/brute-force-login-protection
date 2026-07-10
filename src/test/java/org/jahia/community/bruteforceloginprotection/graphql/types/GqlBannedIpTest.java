package org.jahia.community.bruteforceloginprotection.graphql.types;

import org.jahia.community.bruteforceloginprotection.core.BannedIp;
import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * U2 — {@link GqlBannedIp#getRemainingSeconds()} clamping: future/expired/overflow-adjacent.
 */
public class GqlBannedIpTest {

    private static BannedIp bannedUntil(long bannedUntilMs) {
        return new BannedIp("1.2.3.4", "login", "src", System.currentTimeMillis(), bannedUntilMs, 1, "reason");
    }

    @Test
    public void futureExpiryReturnsApproximateRemainingSeconds() {
        long until = System.currentTimeMillis() + 60_000L;
        GqlBannedIp gql = new GqlBannedIp(bannedUntil(until));

        assertThat(gql.getRemainingSeconds()).isBetween(58, 60);
    }

    @Test
    public void alreadyExpiredClampsToZero() {
        long until = System.currentTimeMillis() - 60_000L;
        GqlBannedIp gql = new GqlBannedIp(bannedUntil(until));

        assertThat(gql.getRemainingSeconds()).isZero();
    }

    @Test
    public void overflowAdjacentClampsToIntegerMax() {
        // bannedUntil far enough in the future that (bannedUntil - now)/1000 exceeds Integer.MAX_VALUE.
        long until = System.currentTimeMillis() + (Long.MAX_VALUE / 2);
        GqlBannedIp gql = new GqlBannedIp(bannedUntil(until));

        assertThat(gql.getRemainingSeconds()).isEqualTo(Integer.MAX_VALUE);
    }

    @Test
    public void delegatesOtherFieldsToInnerBannedIp() {
        BannedIp inner = new BannedIp("9.9.9.9", "login", "manual", 1000L, 2000L, 3, "reason-x");
        GqlBannedIp gql = new GqlBannedIp(inner);

        assertThat(gql.getIp()).isEqualTo("9.9.9.9");
        assertThat(gql.getJail()).isEqualTo("login");
        assertThat(gql.getSource()).isEqualTo("manual");
        assertThat(gql.getBannedAt()).isEqualTo(1000L);
        assertThat(gql.getBannedUntil()).isEqualTo(2000L);
        assertThat(gql.getBanCount()).isEqualTo(3);
        assertThat(gql.getReason()).isEqualTo("reason-x");
    }
}
