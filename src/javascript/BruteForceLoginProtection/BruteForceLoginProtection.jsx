import React, {useEffect, useState} from 'react';
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
        <div className={`${styles.bflp_clusterStatus} ${cls}`} role="status" aria-live="polite">
            {text}
        </div>
    );
};

export const BruteForceLoginProtectionAdmin = () => {
    const {t} = useTranslation('brute-force-login-protection');
    const [activeTab, setActiveTab] = useState(TABS[0].id);
    const [flushStatus, setFlushStatus] = useTransientStatus();
    const [flushAll, {loading: flushing}] = useMutation(FLUSH, {
        refetchQueries: ['GetBannedIps', 'GetTrackedWindows', 'GetAuditLog']
    });

    useEffect(() => {
        document.title = `${t('label.title')} - Jahia Administration`;
    }, [t]);

    const handleFlush = async () => {
        // eslint-disable-next-line no-alert
        if (!window.confirm(t('flush.confirm'))) {
            return;
        }

        try {
            const r = await flushAll();
            setFlushStatus(r.data?.bruteForceLoginProtectionFlush ? 'success' : 'error');
        } catch (err) {
            console.error('Failed to flush:', err);
            setFlushStatus('error');
        }
    };

    const ActiveComponent = TABS.find(t2 => t2.id === activeTab)?.Component || GeneralTab;

    return (
        <div className={styles.bflp_container}>
            <div className={styles.bflp_header}>
                <h2>{t('label.title')}</h2>
            </div>
            <div className={styles.bflp_description}>
                <Typography>{t('label.description')}</Typography>
            </div>

            <ClusterStatusBar/>

            <div className={styles.bflp_tabs} role="tablist" aria-label={t('label.title')}>
                {TABS.map(tab => (
                    <button
                        key={tab.id}
                        type="button"
                        role="tab"
                        id={`bflp-tab-${tab.id}`}
                        aria-controls={`bflp-tabpanel-${tab.id}`}
                        aria-selected={activeTab === tab.id}
                        tabIndex={activeTab === tab.id ? 0 : -1}
                        className={`${styles.bflp_tab} ${activeTab === tab.id ? styles['bflp_tab--active'] : ''}`}
                        onClick={() => setActiveTab(tab.id)}
                    >
                        {t(tab.i18n)}
                    </button>
                ))}
            </div>

            <div
                role="tabpanel"
                id={`bflp-tabpanel-${activeTab}`}
                aria-labelledby={`bflp-tab-${activeTab}`}
            >
                <ActiveComponent/>
            </div>

            <div className={styles.bflp_flushSection}>
                <h3>{t('flush.title')}</h3>
                <Typography>{t('flush.description')}</Typography>
                <StatusAlerts
                    status={flushStatus}
                    successMessage={t('flush.success')}
                    errorMessage={t('flush.error')}
                />
                <button
                    type="button"
                    className={styles.bflp_flushBtn}
                    disabled={flushing}
                    onClick={handleFlush}
                >
                    {flushing ? t('flush.flushing') : t('flush.button')}
                </button>
            </div>
        </div>
    );
};

export default BruteForceLoginProtectionAdmin;
