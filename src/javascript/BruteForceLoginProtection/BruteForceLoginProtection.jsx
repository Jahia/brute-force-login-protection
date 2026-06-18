import React, {useCallback, useEffect, useRef, useState} from 'react';
import {useMutation, useQuery} from '@apollo/client';
import {useTranslation} from 'react-i18next';
import {Typography} from '@jahia/moonstone';
import styles from './BruteForceLoginProtection.scss';
import {FLUSH, GET_CLUSTER_STATUS} from './BruteForceLoginProtection.gql';
import {GeneralTab} from './tabs/GeneralTab';
import {JailsTab} from './tabs/JailsTab';
import {BansTab} from './tabs/BansTab';
import {AuditTab} from './tabs/AuditTab';
import {IntegrationsTab} from './tabs/IntegrationsTab';
import {StatusAlerts} from './tabs/StatusAlerts';
import {useTransientStatus} from './tabs/useTransientStatus';
import {ConfirmDialog} from './ConfirmDialog';

const TABS = [
    {id: 'general', i18n: 'tab.general', Component: GeneralTab},
    {id: 'jails', i18n: 'tab.jails', Component: JailsTab},
    {id: 'bans', i18n: 'tab.bans', Component: BansTab},
    {id: 'audit', i18n: 'tab.audit', Component: AuditTab},
    {id: 'integrations', i18n: 'tab.integrations', Component: IntegrationsTab}
];

const ClusterStatusBar = () => {
    const {t} = useTranslation('brute-force-login-protection');
    const {data} = useQuery(GET_CLUSTER_STATUS, {fetchPolicy: 'network-only'});
    const status = data?.bruteForceLoginProtectionClusterStatus;
    const healthy = status && status.hazelcastRunning && status.nodeCount > 0;
    const text = healthy ?
        t('cluster.healthy', {count: status.nodeCount}) :
        t('cluster.degraded');
    const cls = healthy ? styles['bflp_clusterStatus--healthy'] : styles['bflp_clusterStatus--degraded'];

    return (
        <div aria-live="polite" className={`${styles.bflp_clusterStatus} ${cls}`} role="status">
            {text}
        </div>
    );
};

export const BruteForceLoginProtectionAdmin = () => {
    const {t} = useTranslation('brute-force-login-protection');
    const [activeTab, setActiveTab] = useState(TABS[0].id);
    const [flushStatus, setFlushStatus] = useTransientStatus();
    const [confirmOpen, setConfirmOpen] = useState(false);
    const tabRefs = useRef([]);
    const panelRef = useRef(null);

    const [flushAll, {loading: flushing}] = useMutation(FLUSH, {
        refetchQueries: ['GetBannedIps', 'GetTrackedWindows', 'GetAuditLog']
    });

    useEffect(() => {
        document.title = `${t('label.title')} - Jahia Administration`;
    }, [t]);

    const activeIndex = TABS.findIndex(tab => tab.id === activeTab);

    // F-18: Arrow-key + Home/End roving-tabindex navigation
    const handleTabKeyDown = useCallback(e => {
        let next;
        if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {
            e.preventDefault();
            next = (activeIndex + 1) % TABS.length;
        } else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
            e.preventDefault();
            next = (activeIndex - 1 + TABS.length) % TABS.length;
        } else if (e.key === 'Home') {
            e.preventDefault();
            next = 0;
        } else if (e.key === 'End') {
            e.preventDefault();
            next = TABS.length - 1;
        } else {
            return;
        }

        setActiveTab(TABS[next].id);
        tabRefs.current[next]?.focus();
    }, [activeIndex]);

    // F-20: move focus into the panel on tab activation via keyboard
    const handleTabClick = useCallback(id => {
        setActiveTab(id);
    }, []);

    // F-19: accessible confirm dialog replacing window.confirm
    const handleFlushRequest = () => {
        setConfirmOpen(true);
    };

    const handleFlushConfirm = async () => {
        setConfirmOpen(false);
        try {
            const r = await flushAll();
            setFlushStatus(r.data?.bruteForceLoginProtectionFlush ? 'success' : 'error');
        } catch (err) {
            console.error('Failed to flush:', err);
            setFlushStatus('error');
        }
    };

    const handleFlushCancel = () => {
        setConfirmOpen(false);
    };

    const ActiveComponent = TABS.find(t2 => t2.id === activeTab)?.Component || GeneralTab;
    const activePanelHeading = TABS.find(t2 => t2.id === activeTab)?.i18n;

    return (
        /* F-01/F-03: region landmark with accessible label for the admin panel */
        <div
            aria-label={t('label.title')}
            className={styles.bflp_container}
            role="region"
        >
            <div className={styles.bflp_header}>
                <h2>{t('label.title')}</h2>
            </div>
            <div className={styles.bflp_description}>
                <Typography>{t('label.description')}</Typography>
            </div>

            <ClusterStatusBar/>

            {/* F-18: tablist with arrow-key roving-tabindex */}
            <div aria-label={t('label.title')} className={styles.bflp_tabs} role="tablist">
                {TABS.map((tab, i) => (
                    <button
                        key={tab.id}
                        ref={el => {
                            tabRefs.current[i] = el;
                        }}
                        aria-controls={`bflp-tabpanel-${tab.id}`}
                        aria-selected={activeTab === tab.id}
                        className={`${styles.bflp_tab} ${activeTab === tab.id ? styles['bflp_tab--active'] : ''}`}
                        id={`bflp-tab-${tab.id}`}
                        role="tab"
                        tabIndex={activeTab === tab.id ? 0 : -1}
                        type="button"
                        onClick={() => handleTabClick(tab.id)}
                        onKeyDown={handleTabKeyDown}
                    >
                        {t(tab.i18n)}
                    </button>
                ))}
            </div>

            {/* F-02: visually-hidden h2 owning each tab panel, F-03: region role */}
            <div
                ref={panelRef}
                aria-labelledby={`bflp-tab-${activeTab}`}
                className={styles.bflp_tabPanelWrapper}
                id={`bflp-tabpanel-${activeTab}`}
                role="tabpanel"
                tabIndex={-1}
            >
                <h2 className={styles.bflp_sr_only}>{t(activePanelHeading)}</h2>
                <ActiveComponent/>
            </div>

            {/* Flush section */}
            <div className={styles.bflp_flushSection}>
                <h3 className={styles.bflp_flushSectionHeading}>{t('flush.title')}</h3>
                <Typography>{t('flush.description')}</Typography>
                {/* F-22/F-25/F-26: pre-rendered live regions */}
                <StatusAlerts
                    errorMessage={t('flush.error')}
                    status={flushStatus}
                    successMessage={t('flush.success')}
                />
                <button
                    className={styles.bflp_flushBtn}
                    disabled={flushing}
                    type="button"
                    onClick={handleFlushRequest}
                >
                    {flushing ? t('flush.flushing') : t('flush.button')}
                </button>
            </div>

            {/* F-19/F-30: accessible confirm dialog */}
            <ConfirmDialog
                isOpen={confirmOpen}
                message={t('flush.confirm')}
                onCancel={handleFlushCancel}
                onConfirm={handleFlushConfirm}
            />
        </div>
    );
};

export default BruteForceLoginProtectionAdmin;
