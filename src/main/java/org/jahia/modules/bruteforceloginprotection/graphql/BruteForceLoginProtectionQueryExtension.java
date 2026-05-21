package org.jahia.modules.bruteforceloginprotection.graphql;

import graphql.annotations.annotationTypes.GraphQLDescription;
import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;
import graphql.annotations.annotationTypes.GraphQLTypeExtension;
import org.jahia.modules.bruteforceloginprotection.core.AuditLogger;
import org.jahia.modules.bruteforceloginprotection.core.BannedIp;
import org.jahia.modules.bruteforceloginprotection.core.BruteForceTracker;
import org.jahia.modules.bruteforceloginprotection.core.FailureWindow;
import org.jahia.modules.bruteforceloginprotection.core.JailConfig;
import org.jahia.modules.bruteforceloginprotection.core.SettingsService;
import org.jahia.modules.bruteforceloginprotection.graphql.types.GqlAuditEntry;
import org.jahia.modules.bruteforceloginprotection.graphql.types.GqlBanActionInfo;
import org.jahia.modules.bruteforceloginprotection.graphql.types.GqlBannedIp;
import org.jahia.modules.bruteforceloginprotection.graphql.types.GqlClusterStatus;
import org.jahia.modules.bruteforceloginprotection.graphql.types.GqlFailureWindow;
import org.jahia.modules.bruteforceloginprotection.graphql.types.GqlGlobalSettings;
import org.jahia.modules.bruteforceloginprotection.graphql.types.GqlJail;
import org.jahia.modules.bruteforceloginprotection.hazelcast.HazelcastInstanceManager;
import org.jahia.modules.bruteforceloginprotection.spi.BanAction;
import org.jahia.modules.graphql.provider.dxm.DXGraphQLProvider;
import org.jahia.modules.graphql.provider.dxm.security.GraphQLRequiresPermission;
import org.jahia.osgi.BundleUtils;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

@GraphQLTypeExtension(DXGraphQLProvider.Query.class)
@GraphQLName("BruteForceLoginProtectionQueries")
@GraphQLDescription("Brute Force Login Protection queries")
public class BruteForceLoginProtectionQueryExtension {

    private BruteForceLoginProtectionQueryExtension() {
        // utility
    }

    @GraphQLField
    @GraphQLName("bruteForceLoginProtectionGlobalSettings")
    @GraphQLRequiresPermission("admin")
    public static GqlGlobalSettings globalSettings() {
        SettingsService svc = BundleUtils.getOsgiService(SettingsService.class, null);
        if (svc == null) return null;
        return new GqlGlobalSettings(svc.getGlobalSettings());
    }

    @GraphQLField
    @GraphQLName("bruteForceLoginProtectionJails")
    @GraphQLRequiresPermission("admin")
    public static List<GqlJail> jails() {
        SettingsService svc = BundleUtils.getOsgiService(SettingsService.class, null);
        if (svc == null) return Collections.emptyList();
        List<GqlJail> out = new ArrayList<>();
        for (JailConfig jc : svc.getJails().values()) {
            out.add(new GqlJail(jc));
        }
        return out;
    }

    @GraphQLField
    @GraphQLName("bruteForceLoginProtectionBannedIps")
    @GraphQLRequiresPermission("admin")
    public static List<GqlBannedIp> bannedIps() {
        BruteForceTracker tracker = BundleUtils.getOsgiService(BruteForceTracker.class, null);
        if (tracker == null) return Collections.emptyList();
        Collection<BannedIp> bans = tracker.listBans();
        List<GqlBannedIp> out = new ArrayList<>(bans.size());
        for (BannedIp b : bans) {
            out.add(new GqlBannedIp(b));
        }
        return out;
    }

    @GraphQLField
    @GraphQLName("bruteForceLoginProtectionTrackedWindows")
    @GraphQLRequiresPermission("admin")
    public static List<GqlFailureWindow> trackedWindows() {
        BruteForceTracker tracker = BundleUtils.getOsgiService(BruteForceTracker.class, null);
        if (tracker == null) return Collections.emptyList();
        List<FailureWindow> windows = tracker.listWindows();
        List<GqlFailureWindow> out = new ArrayList<>(windows.size());
        for (FailureWindow w : windows) {
            out.add(new GqlFailureWindow(w));
        }
        return out;
    }

    @GraphQLField
    @GraphQLName("bruteForceLoginProtectionAuditLog")
    @GraphQLRequiresPermission("admin")
    public static List<GqlAuditEntry> auditLog(
            @GraphQLName("limit") Integer limit) {
        AuditLogger audit = BundleUtils.getOsgiService(AuditLogger.class, null);
        if (audit == null) return Collections.emptyList();
        int l = (limit == null || limit <= 0) ? 100 : limit;
        List<AuditLogger.AuditEntry> entries = audit.list(l);
        List<GqlAuditEntry> out = new ArrayList<>(entries.size());
        for (AuditLogger.AuditEntry e : entries) {
            out.add(new GqlAuditEntry(e));
        }
        return out;
    }

    @GraphQLField
    @GraphQLName("bruteForceLoginProtectionBanActions")
    @GraphQLRequiresPermission("admin")
    public static List<GqlBanActionInfo> banActions() {
        BruteForceTracker tracker = BundleUtils.getOsgiService(BruteForceTracker.class, null);
        if (tracker == null) return Collections.emptyList();
        List<GqlBanActionInfo> out = new ArrayList<>();
        for (BanAction a : tracker.getBanActions()) {
            out.add(new GqlBanActionInfo(a.getName(), a.getClass().getName(), a.priority()));
        }
        return out;
    }

    @GraphQLField
    @GraphQLName("bruteForceLoginProtectionClusterStatus")
    @GraphQLRequiresPermission("admin")
    public static GqlClusterStatus clusterStatus() {
        HazelcastInstanceManager hz = BundleUtils.getOsgiService(HazelcastInstanceManager.class, null);
        if (hz == null) return new GqlClusterStatus(false, 0);
        return new GqlClusterStatus(hz.isRunning(), hz.getClusterNodeCount());
    }

}
