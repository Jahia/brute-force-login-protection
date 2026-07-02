package org.jahia.community.bruteforceloginprotection.graphql;

import graphql.annotations.annotationTypes.GraphQLDescription;
import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;
import graphql.annotations.annotationTypes.GraphQLNonNull;
import org.jahia.community.bruteforceloginprotection.actions.EmailBanAction;
import org.jahia.community.bruteforceloginprotection.actions.WebhookBanAction;
import org.jahia.community.bruteforceloginprotection.core.AuditLogger;
import org.jahia.community.bruteforceloginprotection.core.BruteForceTracker;
import org.jahia.community.bruteforceloginprotection.core.GlobalSettingsUpdate;
import org.jahia.community.bruteforceloginprotection.core.IntegrationTestResult;
import org.jahia.community.bruteforceloginprotection.core.SettingsService;
import org.jahia.community.bruteforceloginprotection.core.TorExitNodeFetcher;
import org.jahia.community.bruteforceloginprotection.graphql.types.GqlTestResult;
import org.jahia.modules.graphql.provider.dxm.security.GraphQLRequiresPermission;
import org.jahia.osgi.BundleUtils;

import java.util.List;

@GraphQLName("BruteForceLoginProtectionMutation")
@GraphQLDescription("Brute Force Login Protection mutations")
public class BruteForceLoginProtectionMutation {

    @GraphQLField
    @GraphQLName("saveGlobalSettings")
    @GraphQLRequiresPermission("bruteForceLoginProtectionAdmin")
    @SuppressWarnings("java:S107") // GraphQL schema arity: argument names are part of the public schema
    public Boolean saveGlobalSettings(
            @GraphQLName("activated") Boolean activated,
            @GraphQLName("whitelistIps") String whitelistIps,
            @GraphQLName("ignorePatterns") List<String> ignorePatterns,
            @GraphQLName("trustProxyHeader") Boolean trustProxyHeader,
            @GraphQLName("trustedProxyCidrs") List<String> trustedProxyCidrs,
            @GraphQLName("emailEnabled") Boolean emailEnabled,
            @GraphQLName("emailRecipient") String emailRecipient,
            @GraphQLName("webhookUrl") String webhookUrl,
            @GraphQLName("webhookSecret") @GraphQLDescription("null = leave unchanged; \"\" = clear") String webhookSecret,
            @GraphQLName("auditLogMaxEntries") Integer auditLogMaxEntries,
            @GraphQLName("recidiveFactor") Double recidiveFactor,
            @GraphQLName("maxBanTimeSeconds") Integer maxBanTimeSeconds,
            @GraphQLName("blocklistIps") @GraphQLDescription("Comma-separated always-blocked IPs/CIDRs; \"\" = clear") String blocklistIps,
            @GraphQLName("torBlocklistEnabled") Boolean torBlocklistEnabled,
            @GraphQLName("torBlocklistUrl") String torBlocklistUrl,
            @GraphQLName("torBlocklistRefreshSeconds") Integer torBlocklistRefreshSeconds) {
        SettingsService svc = BundleUtils.getOsgiService(SettingsService.class, null);
        if (svc == null) return Boolean.FALSE;
        GlobalSettingsUpdate update = GlobalSettingsUpdate.builder()
                .activated(activated)
                .whitelistIps(whitelistIps)
                .ignorePatterns(ignorePatterns)
                .trustProxyHeader(trustProxyHeader)
                .trustedProxyCidrs(trustedProxyCidrs)
                .emailEnabled(emailEnabled)
                .emailRecipient(emailRecipient)
                .webhookUrl(webhookUrl)
                .webhookSecret(webhookSecret)
                .auditLogMaxEntries(auditLogMaxEntries)
                .recidiveFactor(recidiveFactor)
                .maxBanTimeSeconds(maxBanTimeSeconds)
                .blocklistIps(blocklistIps)
                .torBlocklistEnabled(torBlocklistEnabled)
                .torBlocklistUrl(torBlocklistUrl)
                .torBlocklistRefreshSeconds(torBlocklistRefreshSeconds)
                .build();
        return svc.saveGlobalSettings(update);
    }

    @GraphQLField
    @GraphQLName("saveJail")
    @GraphQLRequiresPermission("bruteForceLoginProtectionAdmin")
    public Boolean saveJail(
            @GraphQLName("name") @GraphQLNonNull String name,
            @GraphQLName("enabled") Boolean enabled,
            @GraphQLName("maxRetry") Integer maxRetry,
            @GraphQLName("findTimeSeconds") Integer findTimeSeconds,
            @GraphQLName("banTimeSeconds") Integer banTimeSeconds) {
        SettingsService svc = BundleUtils.getOsgiService(SettingsService.class, null);
        if (svc == null) return Boolean.FALSE;
        return svc.saveJail(name, enabled, maxRetry, findTimeSeconds, banTimeSeconds);
    }

    @GraphQLField
    @GraphQLName("deleteJail")
    @GraphQLRequiresPermission("bruteForceLoginProtectionAdmin")
    public Boolean deleteJail(@GraphQLName("name") @GraphQLNonNull String name) {
        SettingsService svc = BundleUtils.getOsgiService(SettingsService.class, null);
        if (svc == null) return Boolean.FALSE;
        return svc.deleteJail(name);
    }

    @GraphQLField
    @GraphQLName("unbanIp")
    @GraphQLRequiresPermission("bruteForceLoginProtectionAdmin")
    public Boolean unbanIp(@GraphQLName("ip") @GraphQLNonNull String ip) {
        BruteForceTracker tracker = BundleUtils.getOsgiService(BruteForceTracker.class, null);
        if (tracker == null) return Boolean.FALSE;
        return tracker.unbanIp(ip);
    }

    @GraphQLField
    @GraphQLName("banIp")
    @GraphQLRequiresPermission("bruteForceLoginProtectionAdmin")
    public Boolean banIp(
            @GraphQLName("ip") @GraphQLNonNull String ip,
            @GraphQLName("jail") String jail,
            @GraphQLName("durationSeconds") Integer durationSeconds,
            @GraphQLName("reason") String reason) {
        BruteForceTracker tracker = BundleUtils.getOsgiService(BruteForceTracker.class, null);
        if (tracker == null) return Boolean.FALSE;
        return tracker.banManually(ip, jail, durationSeconds, reason);
    }

    @GraphQLField
    @GraphQLName("flush")
    @GraphQLDescription("Clear all bans + windows from cluster + JCR")
    @GraphQLRequiresPermission("bruteForceLoginProtectionAdmin")
    public Boolean flush() {
        BruteForceTracker tracker = BundleUtils.getOsgiService(BruteForceTracker.class, null);
        if (tracker == null) return Boolean.FALSE;
        return tracker.flushAll();
    }

    @GraphQLField
    @GraphQLName("clearAuditLog")
    @GraphQLRequiresPermission("bruteForceLoginProtectionAdmin")
    public Boolean clearAuditLog() {
        AuditLogger audit = BundleUtils.getOsgiService(AuditLogger.class, null);
        if (audit == null) return Boolean.FALSE;
        return audit.clear();
    }

    @GraphQLField
    @GraphQLName("testEmail")
    @GraphQLDescription("Sends a synchronous test notification using the currently persisted email settings, bypassing the per-IP throttle.")
    @GraphQLRequiresPermission("bruteForceLoginProtectionAdmin")
    public GqlTestResult testEmail() {
        EmailBanAction action = BundleUtils.getOsgiService(EmailBanAction.class, null);
        if (action == null) {
            return new GqlTestResult(IntegrationTestResult.fail("Email ban action is not registered"));
        }
        return new GqlTestResult(action.sendTest());
    }

    @GraphQLField
    @GraphQLName("refreshTorBlocklist")
    @GraphQLDescription("Synchronously fetches the Tor exit-address list on this node using the currently persisted settings, bypassing the schedule.")
    @GraphQLRequiresPermission("bruteForceLoginProtectionAdmin")
    public GqlTestResult refreshTorBlocklist() {
        TorExitNodeFetcher fetcher = BundleUtils.getOsgiService(TorExitNodeFetcher.class, null);
        if (fetcher == null) {
            return new GqlTestResult(IntegrationTestResult.fail("Tor exit-node fetcher is not registered"));
        }
        return new GqlTestResult(fetcher.forceRefresh());
    }

    @GraphQLField
    @GraphQLName("testWebhook")
    @GraphQLDescription("POSTs a synchronous test payload to the currently persisted webhook URL, applying the same SSRF guard and HMAC signing as the production path.")
    @GraphQLRequiresPermission("bruteForceLoginProtectionAdmin")
    public GqlTestResult testWebhook() {
        WebhookBanAction action = BundleUtils.getOsgiService(WebhookBanAction.class, null);
        if (action == null) {
            return new GqlTestResult(IntegrationTestResult.fail("Webhook ban action is not registered"));
        }
        return new GqlTestResult(action.sendTest());
    }
}
