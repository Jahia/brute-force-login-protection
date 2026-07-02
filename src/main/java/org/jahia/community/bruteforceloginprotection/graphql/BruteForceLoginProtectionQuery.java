package org.jahia.community.bruteforceloginprotection.graphql;

import graphql.annotations.annotationTypes.GraphQLDescription;
import graphql.annotations.annotationTypes.GraphQLField;
import graphql.annotations.annotationTypes.GraphQLName;
import org.jahia.community.bruteforceloginprotection.core.AuditLogger;
import org.jahia.community.bruteforceloginprotection.core.BannedIp;
import org.jahia.community.bruteforceloginprotection.core.BlocklistService;
import org.jahia.community.bruteforceloginprotection.core.BruteForceTracker;
import org.jahia.community.bruteforceloginprotection.core.FailureWindow;
import org.jahia.community.bruteforceloginprotection.core.GlobalConfigHolder;
import org.jahia.community.bruteforceloginprotection.core.GlobalSettings;
import org.jahia.community.bruteforceloginprotection.core.JailConfig;
import org.jahia.community.bruteforceloginprotection.core.JailConfigTracker;
import org.jahia.community.bruteforceloginprotection.core.SettingsService;
import org.jahia.community.bruteforceloginprotection.core.TorExitNodeFetcher;
import org.jahia.community.bruteforceloginprotection.graphql.types.GqlAuditEntry;
import org.jahia.community.bruteforceloginprotection.graphql.types.GqlBanActionInfo;
import org.jahia.community.bruteforceloginprotection.graphql.types.GqlBannedIp;
import org.jahia.community.bruteforceloginprotection.graphql.types.GqlBlocklistStatus;
import org.jahia.community.bruteforceloginprotection.graphql.types.GqlClusterStatus;
import org.jahia.community.bruteforceloginprotection.graphql.types.GqlConfigReadiness;
import org.jahia.community.bruteforceloginprotection.graphql.types.GqlFailureWindow;
import org.jahia.community.bruteforceloginprotection.graphql.types.GqlGlobalSettings;
import org.jahia.community.bruteforceloginprotection.graphql.types.GqlJail;
import org.jahia.community.bruteforceloginprotection.hazelcast.HazelcastInstanceManager;
import org.jahia.community.bruteforceloginprotection.spi.BanAction;
import org.jahia.modules.graphql.provider.dxm.security.GraphQLRequiresPermission;
import org.jahia.osgi.BundleUtils;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

@GraphQLName("BruteForceLoginProtectionQuery")
@GraphQLDescription("Brute Force Login Protection queries")
public class BruteForceLoginProtectionQuery {

    @GraphQLField
    @GraphQLName("globalSettings")
    @GraphQLRequiresPermission("bruteForceLoginProtectionAdmin")
    public GqlGlobalSettings globalSettings() {
        SettingsService svc = BundleUtils.getOsgiService(SettingsService.class, null);
        if (svc == null) return null;
        return new GqlGlobalSettings(svc.getGlobalSettings());
    }

    @GraphQLField
    @GraphQLName("jails")
    @GraphQLRequiresPermission("bruteForceLoginProtectionAdmin")
    public List<GqlJail> jails() {
        SettingsService svc = BundleUtils.getOsgiService(SettingsService.class, null);
        if (svc == null) return Collections.emptyList();
        List<GqlJail> out = new ArrayList<>();
        for (JailConfig jc : svc.getJails().values()) {
            out.add(new GqlJail(jc));
        }
        return out;
    }

    @GraphQLField
    @GraphQLName("bannedIps")
    @GraphQLRequiresPermission("bruteForceLoginProtectionAdmin")
    public List<GqlBannedIp> bannedIps() {
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
    @GraphQLName("trackedWindows")
    @GraphQLRequiresPermission("bruteForceLoginProtectionAdmin")
    public List<GqlFailureWindow> trackedWindows() {
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
    @GraphQLName("auditLog")
    @GraphQLRequiresPermission("bruteForceLoginProtectionAdmin")
    public List<GqlAuditEntry> auditLog(
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
    @GraphQLName("banActions")
    @GraphQLRequiresPermission("bruteForceLoginProtectionAdmin")
    public List<GqlBanActionInfo> banActions() {
        BruteForceTracker tracker = BundleUtils.getOsgiService(BruteForceTracker.class, null);
        if (tracker == null) return Collections.emptyList();
        List<GqlBanActionInfo> out = new ArrayList<>();
        for (BanAction a : tracker.getBanActions()) {
            out.add(new GqlBanActionInfo(a.getName(), a.getClass().getName(), a.priority()));
        }
        return out;
    }

    @GraphQLField
    @GraphQLName("configReady")
    @GraphQLDescription("Readiness probe: globalReady=true once GlobalConfigHolder has received "
            + "its first ConfigurationAdmin update; jailReady=true once a jail config with the "
            + "given name has been registered. Lets clients (notably e2e tests) wait for "
            + "saveGlobalSettings/saveJail mutations to finish propagating before exercising "
            + "the ban path.")
    @GraphQLRequiresPermission("bruteForceLoginProtectionAdmin")
    public GqlConfigReadiness configReady(@GraphQLName("jail") String jail) {
        GlobalConfigHolder global = BundleUtils.getOsgiService(GlobalConfigHolder.class, null);
        JailConfigTracker tracker = BundleUtils.getOsgiService(JailConfigTracker.class, null);
        boolean globalReady = global != null && global.isReady();
        boolean jailReady = tracker != null && jail != null && tracker.hasJail(jail);
        return new GqlConfigReadiness(globalReady, jailReady);
    }

    @GraphQLField
    @GraphQLName("blocklistStatus")
    @GraphQLDescription("Live status of the static + Tor exit-address blocklists on this node: "
            + "entry counts, last fetch time/age, and last fetch error (null when healthy).")
    @GraphQLRequiresPermission("bruteForceLoginProtectionAdmin")
    public GqlBlocklistStatus blocklistStatus() {
        SettingsService svc = BundleUtils.getOsgiService(SettingsService.class, null);
        BlocklistService blocklist = BundleUtils.getOsgiService(BlocklistService.class, null);
        TorExitNodeFetcher fetcher = BundleUtils.getOsgiService(TorExitNodeFetcher.class, null);
        if (svc == null) {
            return null;
        }
        GlobalSettings settings = svc.getGlobalSettings();
        TorExitNodeFetcher.TorStatus tor = fetcher != null
                ? fetcher.getStatus()
                : new TorExitNodeFetcher.TorStatus(0, 0L, 0L, null);
        return new GqlBlocklistStatus(
                blocklist != null ? blocklist.getStaticEntryCount() : 0,
                settings.isTorBlocklistEnabled(),
                settings.getTorBlocklistUrl(),
                settings.getTorBlocklistRefreshSeconds(),
                tor.entryCount(),
                tor.lastSuccessMs(),
                tor.lastAttemptMs(),
                tor.lastError(),
                System.currentTimeMillis());
    }

    @GraphQLField
    @GraphQLName("clusterStatus")
    @GraphQLRequiresPermission("bruteForceLoginProtectionAdmin")
    public GqlClusterStatus clusterStatus() {
        HazelcastInstanceManager hz = BundleUtils.getOsgiService(HazelcastInstanceManager.class, null);
        if (hz == null) return new GqlClusterStatus(false, 0);
        return new GqlClusterStatus(hz.isRunning(), hz.getClusterNodeCount());
    }

}
