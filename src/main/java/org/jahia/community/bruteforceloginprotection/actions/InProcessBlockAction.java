package org.jahia.community.bruteforceloginprotection.actions;

import org.jahia.community.bruteforceloginprotection.core.AuditLogger;
import org.jahia.community.bruteforceloginprotection.core.BanContext;
import org.jahia.community.bruteforceloginprotection.spi.BanAction;
import org.osgi.service.component.annotations.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Default sentinel {@link BanAction} (priority {@code 0}), always registered. This action does
 * <strong>not</strong> perform the block itself — despite its name it only logs the ban/unban
 * event. The actual enforcement is done by {@code AuthValveFailureSource} consulting
 * {@code FailureRecorder.isIpCurrentlyBanned} on every request; the ban entry it reads is written
 * into the distributed map by {@code BruteForceTracker} when the ban is issued.
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
        if (LOGGER.isInfoEnabled()) {
            LOGGER.info("BFLP: IP {} banned (jail={}, banCount={}, until={})",
                    AuditLogger.sanitize(context.getIp()), AuditLogger.sanitize(context.getJailName()),
                    context.getBanCount(), context.getBannedUntil());
        }
    }

    @Override
    public void onUnban(BanContext context) {
        if (LOGGER.isInfoEnabled()) {
            LOGGER.info("BFLP: IP {} unbanned (jail={})",
                    AuditLogger.sanitize(context.getIp()), AuditLogger.sanitize(context.getJailName()));
        }
    }
}
