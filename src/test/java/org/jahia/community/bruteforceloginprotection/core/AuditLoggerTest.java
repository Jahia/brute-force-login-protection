package org.jahia.community.bruteforceloginprotection.core;

import org.jahia.services.content.JCRNodeWrapper;
import org.jahia.services.content.JCRTemplate;
import org.junit.Before;
import org.junit.Test;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.jahia.community.bruteforceloginprotection.BruteForceLoginProtectionConstants.AUDIT_NODE_NAME;
import static org.jahia.community.bruteforceloginprotection.BruteForceLoginProtectionConstants.AUDIT_NODE_PATH;
import static org.jahia.community.bruteforceloginprotection.BruteForceLoginProtectionConstants.NT_AUDIT_CONTAINER;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * F18-a — {@link AuditLogger}'s JCR-backed list/clear/trim/date-bucketing, and U11 — the
 * folder-type upgrade path (a legacy {@code jnt:contentFolder} bucket is detected, deleted, and
 * recreated with the audit-container type) plus cross-date bucketing. Uses {@link FakeJcrNode} as
 * a lightweight in-memory JCR fixture.
 */
@SuppressWarnings("unchecked")
public class AuditLoggerTest {

    private AuditLogger auditLogger;
    private SettingsService settingsService;
    private org.jahia.services.content.JCRSessionWrapper session;
    private FakeJcrNode auditContainer;

    @Before
    public void setUp() throws Exception {
        auditLogger = new AuditLogger();
        JCRTemplate jcrTemplate = mock(JCRTemplate.class);
        settingsService = mock(SettingsService.class);
        inject(auditLogger, "jcrTemplate", jcrTemplate);
        inject(auditLogger, "settingsService", settingsService);

        session = mock(org.jahia.services.content.JCRSessionWrapper.class);
        auditContainer = FakeJcrNode.newRoot(AUDIT_NODE_NAME, NT_AUDIT_CONTAINER);
        auditContainer.bindSession(session);

        when(session.nodeExists(AUDIT_NODE_PATH)).thenReturn(true);
        when(session.getNode(AUDIT_NODE_PATH)).thenReturn(auditContainer.asMock());
        when(settingsService.getOrCreateSettingsNode(any())).thenReturn(mock(JCRNodeWrapper.class));
        when(settingsService.getGlobalSettings()).thenReturn(GlobalSettings.builder()
                .auditLogMaxEntries(1000)
                .build());

        when(jcrTemplate.doExecuteWithSystemSessionAsUser(any(), anyString(), any(), any(org.jahia.services.content.JCRCallback.class)))
                .thenAnswer(inv -> {
                    org.jahia.services.content.JCRCallback<?> cb = inv.getArgument(3);
                    return cb.doInJCR(session);
                });
    }

    private static void inject(Object target, String field, Object value) throws Exception {
        Field f = target.getClass().getDeclaredField(field);
        f.setAccessible(true);
        f.set(target, value);
    }

    private void setMaxEntries(int max) {
        when(settingsService.getGlobalSettings()).thenReturn(GlobalSettings.builder()
                .auditLogMaxEntries(max)
                .build());
    }

    // -------------------------------------------------------------------------------------------
    // F18-a — log/list/clear
    // -------------------------------------------------------------------------------------------

    @Test
    public void logThenListReturnsTheEntryUnderADateBucket() {
        auditLogger.log(AuditLogger.EVENT_BAN, "1.2.3.4", "login", "test-source", "banCount=1");

        List<AuditLogger.AuditEntry> entries = auditLogger.list(10);

        assertThat(entries).hasSize(1);
        AuditLogger.AuditEntry entry = entries.get(0);
        assertThat(entry.getEvent()).isEqualTo(AuditLogger.EVENT_BAN);
        assertThat(entry.getIp()).isEqualTo("1.2.3.4");
        assertThat(entry.getJail()).isEqualTo("login");
        assertThat(entry.getSource()).isEqualTo("test-source");
        assertThat(entry.getDetails()).isEqualTo("banCount=1");
        // Entry must be nested under a yyyy/MM/dd bucket, not a direct child of the container.
        assertThat(auditContainer.childCount()).isEqualTo(1); // just the "yyyy" bucket
    }

    @Test
    public void listRespectsLimitAndOrdersNewestFirst() throws InterruptedException {
        auditLogger.log(AuditLogger.EVENT_FAILURE, "1.1.1.1", "login", "src", "first");
        Thread.sleep(5);
        auditLogger.log(AuditLogger.EVENT_FAILURE, "2.2.2.2", "login", "src", "second");
        Thread.sleep(5);
        auditLogger.log(AuditLogger.EVENT_FAILURE, "3.3.3.3", "login", "src", "third");

        List<AuditLogger.AuditEntry> all = auditLogger.list(100);
        assertThat(all).hasSize(3);
        assertThat(all.get(0).getDetails()).isEqualTo("third");
        assertThat(all.get(2).getDetails()).isEqualTo("first");

        List<AuditLogger.AuditEntry> limited = auditLogger.list(2);
        assertThat(limited).hasSize(2);
        assertThat(limited.get(0).getDetails()).isEqualTo("third");
    }

    @Test
    public void clearRemovesAllEntries() {
        auditLogger.log(AuditLogger.EVENT_BAN, "1.2.3.4", "login", "src", "x");
        assertThat(auditLogger.list(10)).hasSize(1);

        boolean result = auditLogger.clear();

        assertThat(result).isTrue();
        assertThat(auditLogger.list(10)).isEmpty();
    }

    @Test
    public void listOnMissingContainerReturnsEmptyList() throws Exception {
        when(session.nodeExists(AUDIT_NODE_PATH)).thenReturn(false);
        assertThat(auditLogger.list(10)).isEmpty();
    }

    // -------------------------------------------------------------------------------------------
    // F18-a — trimIfNeeded: oldest entries purged once over auditLogMaxEntries, both via the
    // explicit periodic sweep (trimAuditLog) and via the piggyback-every-TRIM_WRITE_INTERVAL path.
    // -------------------------------------------------------------------------------------------

    @Test
    public void trimAuditLogPurgesOldestEntriesOverMax() throws InterruptedException {
        for (int i = 0; i < 8; i++) {
            auditLogger.log(AuditLogger.EVENT_FAILURE, "1.1.1." + i, "login", "src", "entry-" + i);
            Thread.sleep(2);
        }
        setMaxEntries(5);

        auditLogger.trimAuditLog();

        List<AuditLogger.AuditEntry> remaining = auditLogger.list(100);
        assertThat(remaining).hasSize(5);
        // The 5 newest (entry-3..entry-7) must survive; the 3 oldest must be gone.
        assertThat(remaining).extracting(AuditLogger.AuditEntry::getDetails)
                .containsExactlyInAnyOrder("entry-3", "entry-4", "entry-5", "entry-6", "entry-7");
    }

    @Test
    public void piggybackTrimFiresEveryTrimWriteInterval() {
        // TRIM_WRITE_INTERVAL is 50 (private constant); set a low max so the piggyback trim inside
        // the 50th write has a visible effect, then confirm no 51st write was needed to trigger it.
        setMaxEntries(10);
        for (int i = 0; i < 50; i++) {
            auditLogger.log(AuditLogger.EVENT_FAILURE, "9.9.9.9", "login", "src", "w" + i);
        }

        assertThat(auditLogger.list(1000)).hasSize(10);
    }

    // -------------------------------------------------------------------------------------------
    // U11 — folder-type upgrade path: a legacy jnt:contentFolder bucket is detected (empty, wrong
    // type), removed, and recreated with the audit-container type.
    // -------------------------------------------------------------------------------------------

    @Test
    public void legacyContentFolderBucketIsUpgradedOnNextWrite() throws Exception {
        ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC);
        String year = now.format(java.time.format.DateTimeFormatter.ofPattern("yyyy"));
        String month = now.format(java.time.format.DateTimeFormatter.ofPattern("MM"));
        String day = now.format(java.time.format.DateTimeFormatter.ofPattern("dd"));

        JCRNodeWrapper yearNode = auditContainer.asMock().addNode(year, NT_AUDIT_CONTAINER);
        JCRNodeWrapper monthNode = yearNode.addNode(month, NT_AUDIT_CONTAINER);
        // Legacy, empty, wrong-typed day bucket -- simulates a pre-upgrade module version.
        monthNode.addNode(day, "jnt:contentFolder");

        auditLogger.log(AuditLogger.EVENT_BAN, "5.5.5.5", "login", "src", "after-upgrade");

        JCRNodeWrapper upgradedDay = monthNode.getNode(day);
        assertThat(upgradedDay.isNodeType(NT_AUDIT_CONTAINER)).isTrue();
        assertThat(upgradedDay.isNodeType("jnt:contentFolder")).isFalse();

        List<AuditLogger.AuditEntry> entries = auditLogger.list(10);
        assertThat(entries).hasSize(1);
        assertThat(entries.get(0).getDetails()).isEqualTo("after-upgrade");
    }

    @Test
    public void correctlyTypedBucketIsReusedNotRecreated() throws Exception {
        ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC);
        String year = now.format(java.time.format.DateTimeFormatter.ofPattern("yyyy"));
        JCRNodeWrapper yearNode = auditContainer.asMock().addNode(year, NT_AUDIT_CONTAINER);

        auditLogger.log(AuditLogger.EVENT_BAN, "6.6.6.6", "login", "src", "reused-bucket");

        // Exactly one "yyyy" child overall -- the pre-created year folder was reused, not
        // duplicated alongside a second one.
        assertThat(auditContainer.childCount()).isEqualTo(1);
        assertThat(yearNode.hasNode(now.format(java.time.format.DateTimeFormatter.ofPattern("MM")))).isTrue();
    }

    // -------------------------------------------------------------------------------------------
    // U11 residual — different dates land in different yyyy/MM/dd buckets. Exercised directly
    // against the private static getOrCreateDateBucket(), since AuditLogger.log() always uses
    // System.currentTimeMillis() internally and this module has no injectable clock.
    // -------------------------------------------------------------------------------------------

    @Test
    public void differentEpochsProduceDifferentDateBuckets() throws Exception {
        Method m = AuditLogger.class.getDeclaredMethod("getOrCreateDateBucket", JCRNodeWrapper.class, long.class);
        m.setAccessible(true);

        long epoch2020 = java.time.Instant.parse("2020-01-15T00:00:00Z").toEpochMilli();
        long epoch2023 = java.time.Instant.parse("2023-06-30T00:00:00Z").toEpochMilli();

        JCRNodeWrapper bucket2020 = (JCRNodeWrapper) m.invoke(null, auditContainer.asMock(), epoch2020);
        JCRNodeWrapper bucket2023 = (JCRNodeWrapper) m.invoke(null, auditContainer.asMock(), epoch2023);

        assertThat(bucket2020).isNotSameAs(bucket2023);
        assertThat(auditContainer.childCount()).isEqualTo(2); // "2020" and "2023"
        assertThat(auditContainer.asMock().hasNode("2020")).isTrue();
        assertThat(auditContainer.asMock().hasNode("2023")).isTrue();
    }
}
