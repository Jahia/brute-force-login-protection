package org.jahia.modules.bruteforceloginprotection.actions;

import com.hazelcast.core.HazelcastInstance;
import com.hazelcast.core.IMap;
import org.apache.commons.lang.StringUtils;
import org.jahia.modules.bruteforceloginprotection.BruteForceLoginProtectionConstants;
import org.jahia.modules.bruteforceloginprotection.core.AuditLogger;
import org.jahia.modules.bruteforceloginprotection.core.BanContext;
import org.jahia.modules.bruteforceloginprotection.core.GlobalSettings;
import org.jahia.modules.bruteforceloginprotection.core.IntegrationTestResult;
import org.jahia.modules.bruteforceloginprotection.core.SettingsService;
import org.jahia.modules.bruteforceloginprotection.hazelcast.HazelcastInstanceManager;
import org.jahia.modules.bruteforceloginprotection.spi.BanAction;
import org.jahia.services.mail.MailService;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.TimeUnit;

@Component(immediate = true, service = {BanAction.class, EmailBanAction.class})
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
        } catch (Exception t) {
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
            String recipient = stripHeaderInjection(StringUtils.defaultIfBlank(settings.getEmailRecipient(), mailService.defaultRecipient()));
            String sender = stripHeaderInjection(mailService.defaultSender());
            String subject = stripHeaderInjection(String.format("[BFLP] Login blocked for IP %s", AuditLogger.sanitize(context.getIp())));
            String body = "The IP " + AuditLogger.sanitize(context.getIp()) + " was banned by jail '" + AuditLogger.sanitize(context.getJailName())
                    + "' (banCount=" + context.getBanCount()
                    + ", until=" + context.getBannedUntil() + ").\n"
                    + "Reason: " + AuditLogger.sanitize(context.getReason());
            mailService.sendMessage(sender, recipient, null, null, subject, body);
        } catch (Exception e) {
            LOGGER.warn("BFLP: error sending ban notification email: {}", e.getMessage());
        }
    }

    @Override
    public void onUnban(BanContext context) {
        // no email on unban
    }

    /**
     * Sends a synchronous test email using the currently persisted settings, bypassing the
     * per-IP throttle. Intended for the admin UI "Send test email" button.
     */
    public IntegrationTestResult sendTest() {
        GlobalSettings settings = settingsService.getGlobalSettings();
        MailService mailService;
        try {
            mailService = MailService.getInstance();
        } catch (Exception t) {
            return IntegrationTestResult.fail("MailService unavailable: " + t.getMessage());
        }
        if (mailService == null) {
            return IntegrationTestResult.fail("MailService is not registered");
        }
        if (!mailService.isEnabled()) {
            return IntegrationTestResult.fail("Jahia mail service is disabled (configure SMTP in server settings)");
        }
        String recipient = stripHeaderInjection(StringUtils.defaultIfBlank(
                settings.getEmailRecipient(), mailService.defaultRecipient()));
        if (StringUtils.isBlank(recipient)) {
            return IntegrationTestResult.fail("No recipient configured (set one above or in Jahia mail settings)");
        }
        try {
            String sender = stripHeaderInjection(mailService.defaultSender());
            String subject = stripHeaderInjection("[BFLP] Test notification");
            String body = "This is a test notification from Brute Force Login Protection. "
                    + "If you received it, the email integration is working.";
            mailService.sendMessage(sender, recipient, null, null, subject, body);
            return IntegrationTestResult.ok("Test email sent to " + recipient);
        } catch (Exception e) {
            LOGGER.warn("BFLP: test email failed: {}", e.getMessage());
            return IntegrationTestResult.fail("Send failed: " + e.getMessage());
        }
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

    /**
     * Strips CR/LF and their percent-encoded equivalents to prevent SMTP header injection
     * when an attacker controls the configured recipient (e.g., via a compromised admin UI).
     */
    static String stripHeaderInjection(String value) {
        if (value == null) {
            return null;
        }
        return StringUtils.replaceEach(value,
                new String[]{"\r", "\n", "%0a", "%0A", "%0d", "%0D"},
                new String[]{"", "", "", "", "", ""});
    }
}
