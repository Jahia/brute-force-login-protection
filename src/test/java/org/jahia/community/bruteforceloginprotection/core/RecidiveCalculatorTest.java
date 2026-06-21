package org.jahia.community.bruteforceloginprotection.core;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class RecidiveCalculatorTest {

    @Test
    public void firstBanReturnsBaseBanTime() {
        // prevBanCount = 0 -> no multiplication
        assertThat(RecidiveCalculator.next(0, 60L, 2.0, 0L)).isEqualTo(60L);
    }

    @Test
    public void secondBanMultipliesByFactor() {
        // prevBanCount = 1 -> base * factor
        assertThat(RecidiveCalculator.next(1, 60L, 2.0, 0L)).isEqualTo(120L);
    }

    @Test
    public void thirdBanMultipliesTwice() {
        // prevBanCount = 2 -> base * factor * factor
        assertThat(RecidiveCalculator.next(2, 60L, 2.0, 0L)).isEqualTo(240L);
    }

    @Test
    public void cappedAtMaxBanTime() {
        // base 60 * 2^10 = 61440, capped at 1000
        assertThat(RecidiveCalculator.next(10, 60L, 2.0, 1000L)).isEqualTo(1000L);
    }

    @Test
    public void capZeroMeansNoCap() {
        // cap = 0 -> unlimited
        assertThat(RecidiveCalculator.next(3, 10L, 2.0, 0L)).isEqualTo(80L);
    }

    @Test
    public void factorBelowOneBehavesAsOne() {
        // factor < 1.0 normalized to 1.0 -> duration stays = base
        assertThat(RecidiveCalculator.next(5, 60L, 0.5, 0L)).isEqualTo(60L);
        assertThat(RecidiveCalculator.next(5, 60L, 0.0, 0L)).isEqualTo(60L);
    }

    @Test
    public void zeroOrNegativeBaseUsesOne() {
        // baseBanTimeSec <= 0 normalized to 1
        assertThat(RecidiveCalculator.next(0, 0L, 2.0, 0L)).isEqualTo(1L);
        assertThat(RecidiveCalculator.next(0, -5L, 2.0, 0L)).isEqualTo(1L);
        // 1 * 2 * 2 = 4
        assertThat(RecidiveCalculator.next(2, 0L, 2.0, 0L)).isEqualTo(4L);
    }

    @Test
    public void factorOneNeverGrows() {
        assertThat(RecidiveCalculator.next(100, 30L, 1.0, 0L)).isEqualTo(30L);
    }
}
