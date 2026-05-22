package org.jahia.modules.bruteforceloginprotection.core;

public final class RecidiveCalculator {

    private RecidiveCalculator() {}

    public static long next(int prevBanCount, long baseBanTimeSec, double factor, long capSec) {
        if (baseBanTimeSec <= 0) {
            baseBanTimeSec = 1;
        }
        if (factor < 1.0) {
            factor = 1.0;
        }
        double duration = baseBanTimeSec;
        for (int i = 0; i < prevBanCount; i++) {
            duration *= factor;
            if (capSec > 0 && duration >= capSec) {
                return capSec;
            }
        }
        long result = (long) Math.min(duration, Long.MAX_VALUE);
        if (capSec > 0 && result > capSec) {
            return capSec;
        }
        return result;
    }
}
