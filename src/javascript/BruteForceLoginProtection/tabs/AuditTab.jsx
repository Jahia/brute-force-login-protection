import React, {useState} from 'react';
import {useMutation, useQuery} from '@apollo/client';
import {useTranslation} from 'react-i18next';
import {Loader, Typography} from '@jahia/moonstone';
import styles from '../BruteForceLoginProtection.scss';
import {CLEAR_AUDIT_LOG, GET_AUDIT_LOG} from '../BruteForceLoginProtection.gql';
import {StatusAlerts} from './StatusAlerts';
import {formatEpoch, useTransientStatus} from './useTransientStatus';

const LIMITS = [50, 100, 200, 500];

const eventClass = event => {
    if (!event) {
        return styles['bflp_eventBadge--default'];
    }

    const e = event.toUpperCase();
    if (e === 'BAN' || e.startsWith('BAN_')) {
        return styles['bflp_eventBadge--ban'];
    }

    if (e === 'UNBAN' || e.startsWith('UNBAN_')) {
        return styles['bflp_eventBadge--unban'];
    }

    if (e === 'FAILURE' || e.includes('FAIL')) {
        return styles['bflp_eventBadge--failure'];
    }

    if (e === 'CONFIG_CHANGE' || e.startsWith('CONFIG')) {
        return styles['bflp_eventBadge--config'];
    }

    return styles['bflp_eventBadge--default'];
};

export const AuditTab = () => {
    const {t} = useTranslation('brute-force-login-protection');
    const [limit, setLimit] = useState(100);
    const [status, setStatus] = useTransientStatus();

    const {data, loading} = useQuery(GET_AUDIT_LOG, {
        variables: {limit},
        fetchPolicy: 'network-only'
    });
    const [clearLog, {loading: clearing}] = useMutation(CLEAR_AUDIT_LOG, {
        refetchQueries: ['GetAuditLog']
    });

    const handleClear = async () => {
        // eslint-disable-next-line no-alert
        if (!window.confirm(t('audit.confirmClear'))) {
            return;
        }

        try {
            const r = await clearLog();
            setStatus(r.data?.bruteForceLoginProtectionClearAuditLog ? 'success' : 'error');
        } catch (err) {
            console.error('Failed to clear audit log:', err);
            setStatus('error');
        }
    };

    const entries = data?.bruteForceLoginProtectionAuditLog || [];

    return (
        <div className={styles.bflp_tabPanel}>
            <div className={styles.bflp_sectionHeader}>
                <h3>{t('audit.title')}</h3>
                <div className={styles.bflp_inlineActions}>
                    <label className={styles.bflp_label} htmlFor="bflp-audit-limit">{t('audit.limit')}</label>
                    <select
                        id="bflp-audit-limit"
                        className={styles.bflp_select}
                        value={limit}
                        onChange={e => setLimit(Number.parseInt(e.target.value, 10))}
                    >
                        {LIMITS.map(n => (
                            <option key={n} value={n}>{n}</option>
                        ))}
                    </select>
                    <button
                        type="button"
                        className={styles.bflp_unbanBtn}
                        disabled={clearing}
                        onClick={handleClear}
                    >
                        {clearing ? t('audit.clearing') : t('audit.clear')}
                    </button>
                </div>
            </div>
            <Typography className={styles.bflp_description}>{t('audit.description')}</Typography>
            <StatusAlerts status={status}/>

            {loading && (
                <div className={styles.bflp_loading} aria-busy="true" aria-live="polite">
                    <Loader size="big"/>
                    <span className={styles.bflp_sr_only}>{t('label.loading')}</span>
                </div>
            )}

            {!loading && entries.length === 0 && (
                <Typography className={styles.bflp_emptyState}>{t('audit.noEntries')}</Typography>
            )}

            {!loading && entries.length > 0 && (
                <table className={styles.bflp_table}>
                    <thead>
                        <tr>
                            <th scope="col">{t('audit.colTimestamp')}</th>
                            <th scope="col">{t('audit.colEvent')}</th>
                            <th scope="col">{t('audit.colIp')}</th>
                            <th scope="col">{t('audit.colJail')}</th>
                            <th scope="col">{t('audit.colSource')}</th>
                            <th scope="col">{t('audit.colDetails')}</th>
                        </tr>
                    </thead>
                    <tbody>
                        {entries.map(entry => (
                            <tr key={entry.id}>
                                <td>{formatEpoch(entry.timestamp)}</td>
                                <td>
                                    <span className={`${styles.bflp_eventBadge} ${eventClass(entry.event)}`}>
                                        {entry.event}
                                    </span>
                                </td>
                                <td className={styles.bflp_ipCell}>{entry.ip || ''}</td>
                                <td>{entry.jail || ''}</td>
                                <td>{entry.source || ''}</td>
                                <td>{entry.details || ''}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            )}
        </div>
    );
};

export default AuditTab;
