package org.jahia.modules.bruteforceloginprotection.graphql;

import graphql.annotations.annotationTypes.GraphQLDescription;
import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;
import graphql.annotations.annotationTypes.GraphQLNonNull;
import graphql.annotations.annotationTypes.GraphQLTypeExtension;
import org.jahia.modules.bruteforceloginprotection.core.AuditLogger;
import org.jahia.modules.bruteforceloginprotection.core.BruteForceTracker;
import org.jahia.modules.bruteforceloginprotection.core.GlobalSettingsUpdate;
import org.jahia.modules.bruteforceloginprotection.core.SettingsService;
import org.jahia.modules.graphql.provider.dxm.DXGraphQLProvider;
import org.jahia.modules.graphql.provider.dxm.security.GraphQLRequiresPermission;
import org.jahia.osgi.BundleUtils;

import java.util.List;

@GraphQLTypeExtension(DXGraphQLProvider.Mutation.class)
@GraphQLName("BruteForceLoginProtectionMutations")
@GraphQLDescription("Brute Force Login Protection mutations")
public class BruteForceLoginProtectionMutationExtension {

    private BruteForceLoginProtectionMutationExtension() {
        // utility
    }

    @GraphQLField
    @GraphQLName("bruteForceLoginProtectionSaveGlobalSettings")
    @GraphQLRequiresPermission("admin")
    @SuppressWarnings("java:S107") // GraphQL schema arity: argument names are part of the public schema
    public static Boolean saveGlobalSettings(
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
            @GraphQLName("maxBanTimeSeconds") Integer maxBanTimeSeconds) {
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
                .build();
        return svc.saveGlobalSettings(update);
    }

    @GraphQLField
    @GraphQLName("bruteForceLoginProtectionSaveJail")
    @GraphQLRequiresPermission("admin")
    public static Boolean saveJail(
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
    @GraphQLName("bruteForceLoginProtectionDeleteJail")
    @GraphQLRequiresPermission("admin")
    public static Boolean deleteJail(@GraphQLName("name") @GraphQLNonNull String name) {
        SettingsService svc = BundleUtils.getOsgiService(SettingsService.class, null);
        if (svc == null) return Boolean.FALSE;
        return svc.deleteJail(name);
    }

    @GraphQLField
    @GraphQLName("bruteForceLoginProtectionUnbanIp")
    @GraphQLRequiresPermission("admin")
    public static Boolean unbanIp(@GraphQLName("ip") @GraphQLNonNull String ip) {
        BruteForceTracker tracker = BundleUtils.getOsgiService(BruteForceTracker.class, null);
        if (tracker == null) return Boolean.FALSE;
        return tracker.unbanIp(ip);
    }

    @GraphQLField
    @GraphQLName("bruteForceLoginProtectionBanIp")
    @GraphQLRequiresPermission("admin")
    public static Boolean banIp(
            @GraphQLName("ip") @GraphQLNonNull String ip,
            @GraphQLName("jail") String jail,
            @GraphQLName("durationSeconds") Integer durationSeconds,
            @GraphQLName("reason") String reason) {
        BruteForceTracker tracker = BundleUtils.getOsgiService(BruteForceTracker.class, null);
        if (tracker == null) return Boolean.FALSE;
        return tracker.banManually(ip, jail, durationSeconds, reason);
    }

    @GraphQLField
    @GraphQLName("bruteForceLoginProtectionFlush")
    @GraphQLDescription("Clear all bans + windows from cluster + JCR")
    @GraphQLRequiresPermission("admin")
    public static Boolean flush() {
        BruteForceTracker tracker = BundleUtils.getOsgiService(BruteForceTracker.class, null);
        if (tracker == null) return Boolean.FALSE;
        return tracker.flushAll();
    }

    @GraphQLField
    @GraphQLName("bruteForceLoginProtectionClearAuditLog")
    @GraphQLRequiresPermission("admin")
    public static Boolean clearAuditLog() {
        AuditLogger audit = BundleUtils.getOsgiService(AuditLogger.class, null);
        if (audit == null) return Boolean.FALSE;
        return audit.clear();
    }
}
