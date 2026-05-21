package org.jahia.modules.bruteforceloginprotection.actions;

import org.jahia.modules.bruteforceloginprotection.core.BanContext;
import org.jahia.modules.bruteforceloginprotection.spi.BanAction;
import org.osgi.service.component.annotations.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Default sentinel BanAction. Always-on. The actual valve-side block is done by
 * AuthValveFailureSource consulting FailureRecorder.isIpCurrentlyBanned.
 */
@Component(immediate = true, service = BanAction.class)
public class InProcessBlockAction implements BanAction {

    private static final Logger LOGGER = LoggerFactory.getLogger(InProcessBlockAction.class);

    @Override
    public String getName() {
        return "in-process-block";
    }

    @Override
    public int priority() {
        return 0;
    }

    @Override
    public void onBan(BanContext context) {
        LOGGER.info("BFLP: IP {} banned (jail={}, banCount={}, until={})",
                sanitize(context.getIp()), sanitize(context.getJailName()),
                context.getBanCount(), context.getBannedUntil());
    }

    @Override
    public void onUnban(BanContext context) {
        LOGGER.info("BFLP: IP {} unbanned (jail={})",
                sanitize(context.getIp()), sanitize(context.getJailName()));
    }

    private static String sanitize(String s) {
        return s == null ? null : s.replaceAll("[\r\n]", "");
    }
}
