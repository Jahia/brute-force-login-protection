package org.jahia.modules.bruteforceloginprotection.actions;

import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.core.IMap;
import org.apache.commons.lang.StringUtils;
import org.jahia.modules.bruteforceloginprotection.BruteForceLoginProtectionConstants;
import org.jahia.modules.bruteforceloginprotection.core.BanContext;
import org.jahia.modules.bruteforceloginprotection.core.GlobalSettings;
import org.jahia.modules.bruteforceloginprotection.core.SettingsService;
import org.jahia.modules.bruteforceloginprotection.hazelcast.HazelcastInstanceManager;
import org.jahia.modules.bruteforceloginprotection.spi.BanAction;
import org.jahia.services.mail.MailService;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.TimeUnit;

@Component(immediate = true, service = BanAction.class)
public class EmailBanAction implements BanAction {

    private static final Logger LOGGER = LoggerFactory.getLogger(EmailBanAction.class);

    @Reference
    private SettingsService settingsService;

    @Reference
    private HazelcastInstanceManager hazelcastManager;

    @Override
    public String getName() {
        return "email";
    }

    @Override
    public int priority() {
        return 10;
    }

    @Override
    public void onBan(BanContext context) {
        GlobalSettings settings = settingsService.getGlobalSettings();
        if (!settings.isEmailEnabled()) {
            return;
        }
        MailService mailService;
        try {
            mailService = MailService.getInstance();
        } catch (Throwable t) {
            LOGGER.debug("BFLP: MailService unavailable: {}", t.getMessage());
            return;
        }
        if (mailService == null || !mailService.isEnabled()) {
            return;
        }
        if (!throttle(context.getIp())) {
            return;
        }
        try {
            String recipient = StringUtils.defaultIfBlank(settings.getEmailRecipient(), mailService.defaultRecipient());
            String sender = mailService.defaultSender();
            String subject = String.format("[BFLP] Login blocked for IP %s", sanitize(context.getIp()));
            String body = "The IP " + sanitize(context.getIp()) + " was banned by jail '" + sanitize(context.getJailName())
                    + "' (banCount=" + context.getBanCount()
                    + ", until=" + context.getBannedUntil() + ").\n"
                    + "Reason: " + sanitize(context.getReason());
            mailService.sendMessage(sender, recipient, null, null, subject, body);
        } catch (Exception e) {
            LOGGER.warn("BFLP: error sending ban notification email: {}", e.getMessage());
        }
    }

    @Override
    public void onUnban(BanContext context) {
        // no email on unban
    }

    private boolean throttle(String ip) {
        HazelcastInstance hz = hazelcastManager.getHazelcastInstance();
        if (hz == null) {
            return true;
        }
        IMap<String, Long> markers = hz.getMap(BruteForceLoginProtectionConstants.MAP_NOTIFICATION_MARKERS);
        Long existing = markers.putIfAbsent(ip, System.currentTimeMillis(),
                BruteForceLoginProtectionConstants.NOTIFICATION_THROTTLE_SECONDS, TimeUnit.SECONDS);
        return existing == null;
    }

    private static String sanitize(String s) {
        return s == null ? null : s.replaceAll("[\r\n]", "");
    }
}
