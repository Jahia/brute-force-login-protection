import React, {useState} from 'react';
import {useMutation, useQuery} from '@apollo/client';
import {useTranslation} from 'react-i18next';
import {Button, Loader, Typography} from '@jahia/moonstone';
import styles from './BruteForceLoginProtection.scss';
import {
    FLUSH_CACHE,
    GET_SETTINGS,
    GET_TRACKED_IPS,
    SAVE_SETTINGS,
    UNBLOCK_IP
} from './BruteForceLoginProtection.gql';

export const BruteForceLoginProtectionAdmin = () => {
    const {t} = useTranslation('brute-force-login-protection');
    const [saveStatus, setSaveStatus] = useState(null);
    const [flushStatus, setFlushStatus] = useState(null);
    const [validationError, setValidationError] = useState(null);

    const [formState, setFormState] = useState({
        activated: false,
        nbFailedLoginMax: 6,
        whitelistIps: '127.0.0.1/32,::1/128',
        timeToIdle: 3600
    });

    const {loading} = useQuery(GET_SETTINGS, {
        fetchPolicy: 'network-only',
        onCompleted: data => {
            const s = data?.bruteForceLoginProtectionSettings;
            if (s) {
                setFormState({
                    activated: s.activated,
                    nbFailedLoginMax: s.nbFailedLoginMax,
                    whitelistIps: s.whitelistIps,
                    timeToIdle: s.timeToIdle ?? 3600
                });
            }
        }
    });

    const [saveSettings, {loading: saving}] = useMutation(SAVE_SETTINGS);
    const [flushCache, {loading: flushing}] = useMutation(FLUSH_CACHE);

    const {
        data: trackedData,
        loading: trackedLoading,
        refetch: refetchTracked
    } = useQuery(GET_TRACKED_IPS, {fetchPolicy: 'network-only'});

    const [unblockIp, {loading: unblocking}] = useMutation(UNBLOCK_IP);
    const [unblockingIp, setUnblockingIp] = useState(null);

    const handleUnblock = async ip => {
        setUnblockingIp(ip);
        try {
            await unblockIp({variables: {ip}});
            await refetchTracked();
        } catch (err) {
            console.error('Failed to unblock IP:', err);
        } finally {
            setUnblockingIp(null);
        }
    };

    const handleSave = async () => {
        setSaveStatus(null);
        setValidationError(null);

        if (formState.activated && !formState.whitelistIps.trim()) {
            setValidationError(t('label.errorWhitelistRequired'));
            return;
        }

        try {
            const result = await saveSettings({
                variables: {
                    activated: formState.activated,
                    nbFailedLoginMax: formState.nbFailedLoginMax,
                    whitelistIps: formState.whitelistIps,
                    timeToIdle: formState.timeToIdle
                }
            });
            setSaveStatus(result.data?.bruteForceLoginProtectionSaveSettings ? 'success' : 'error');
        } catch (err) {
            console.error('Failed to save settings:', err);
            setSaveStatus('error');
        }
    };

    const handleFlush = async () => {
        setFlushStatus(null);
        try {
            const result = await flushCache();
            setFlushStatus(result.data?.bruteForceLoginProtectionFlushCache ? 'success' : 'error');
        } catch (err) {
            console.error('Failed to flush cache:', err);
            setFlushStatus('error');
        }
    };

    if (loading) {
        return (
            <div className={styles.bflp_loading}>
                <Loader size="big"/>
            </div>
        );
    }

    const trackedRows = trackedData?.bruteForceLoginProtectionTrackedIps;
    let trackedContent;
    if (trackedLoading && !trackedRows) {
        trackedContent = (
            <div className={styles.bflp_loading}>
                <Loader size="big"/>
            </div>
        );
    } else if (trackedRows?.length > 0) {
        trackedContent = (
            <table className={styles.bflp_table}>
                <thead>
                    <tr>
                        <th>{t('label.colIp')}</th>
                        <th>{t('label.colFailedLogins')}</th>
                        <th>{t('label.colStatus')}</th>
                        <th>{t('label.colActions')}</th>
                    </tr>
                </thead>
                <tbody>
                    {trackedRows.map(row => (
                        <tr key={row.ip}>
                            <td className={styles.bflp_ipCell}>{row.ip}</td>
                            <td>{row.nbFailedLogins}</td>
                            <td>
                                <span className={`${styles.bflp_badge} ${row.blocked ? styles['bflp_badge--blocked'] : styles['bflp_badge--tracked']}`}>
                                    {row.blocked ? t('label.statusBlocked') : t('label.statusTracked')}
                                </span>
                            </td>
                            <td>
                                <button
                                    type="button"
                                    className={styles.bflp_unblockBtn}
                                    disabled={unblocking && unblockingIp === row.ip}
                                    onClick={() => handleUnblock(row.ip)}
                                >
                                    {unblocking && unblockingIp === row.ip ? t('label.unblocking') : t('label.unblock')}
                                </button>
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
        );
    } else {
        trackedContent = (
            <Typography className={styles.bflp_emptyState}>{t('label.noTrackedIps')}</Typography>
        );
    }

    return (
        <div className={styles.bflp_container}>
            <div className={styles.bflp_header}>
                <h2>{t('label.title')}</h2>
            </div>

            <div className={styles.bflp_description}>
                <Typography>{t('label.description')}</Typography>
            </div>

            <div className={styles.bflp_form}>
                <div className={styles.bflp_fieldGroup}>
                    <span className={styles.bflp_label}>{t('label.serviceStatus')}</span>
                    <label className={styles.bflp_toggle} aria-label={t('label.serviceStatus')}>
                        <input
                            type="checkbox"
                            checked={formState.activated}
                            onChange={e => setFormState(prev => ({...prev, activated: e.target.checked}))}
                        />
                        <span className={styles.bflp_toggleSlider}/>
                    </label>
                </div>

                <div className={styles.bflp_fieldGroup}>
                    <label className={styles.bflp_label} htmlFor="bflp-max">
                        {t('label.nbFailedLoginMax')}
                    </label>
                    <input
                        type="number"
                        id="bflp-max"
                        className={styles.bflp_input}
                        min="1"
                        value={formState.nbFailedLoginMax}
                        onChange={e => setFormState(prev => ({
                            ...prev,
                            nbFailedLoginMax: Number.parseInt(e.target.value, 10) || 1
                        }))}
                    />
                </div>

                <div className={styles.bflp_fieldGroup}>
                    <label className={styles.bflp_label} htmlFor="bflp-whitelist">
                        {t('label.whitelistIps')}
                        <span className={styles.bflp_tooltip} title={t('label.whitelistIpsTooltip')}>ⓘ</span>
                    </label>
                    <textarea
                        id="bflp-whitelist"
                        className={styles.bflp_textarea}
                        rows={6}
                        value={formState.whitelistIps}
                        onChange={e => setFormState(prev => ({...prev, whitelistIps: e.target.value}))}
                    />
                </div>

                <div className={styles.bflp_fieldGroup}>
                    <label className={styles.bflp_label} htmlFor="bflp-tti">
                        {t('label.timeToIdle')}
                        <span className={styles.bflp_tooltip} title={t('label.timeToIdleTooltip')}>ⓘ</span>
                    </label>
                    <input
                        type="number"
                        id="bflp-tti"
                        className={styles.bflp_input}
                        min="1"
                        value={formState.timeToIdle}
                        onChange={e => setFormState(prev => ({
                            ...prev,
                            timeToIdle: Number.parseInt(e.target.value, 10) || 3600
                        }))}
                    />
                </div>
            </div>

            <div className={styles.bflp_actions}>
                {validationError && (
                    <div className={`${styles.bflp_alert} ${styles['bflp_alert--error']}`}>
                        {validationError}
                    </div>
                )}
                {saveStatus === 'success' && (
                    <div className={`${styles.bflp_alert} ${styles['bflp_alert--success']}`}>
                        {t('label.saveSuccess')}
                    </div>
                )}
                {saveStatus === 'error' && (
                    <div className={`${styles.bflp_alert} ${styles['bflp_alert--error']}`}>
                        {t('label.saveError')}
                    </div>
                )}
                <Button
                    label={t('label.save')}
                    variant="primary"
                    isDisabled={saving}
                    onClick={handleSave}
                />
            </div>

            <div className={styles.bflp_trackedSection}>
                <div className={styles.bflp_sectionHeader}>
                    <h3>{t('label.trackedIpsTitle')}</h3>
                    <button
                        type="button"
                        className={styles.bflp_refreshBtn}
                        disabled={trackedLoading}
                        onClick={() => refetchTracked()}
                    >
                        {trackedLoading ? t('label.refreshing') : t('label.refresh')}
                    </button>
                </div>
                <Typography>{t('label.trackedIpsDescription')}</Typography>
                {trackedContent}
            </div>

            <div className={styles.bflp_flushSection}>
                <Typography>{t('label.flushDescription')}</Typography>
                {flushStatus === 'success' && (
                    <div className={`${styles.bflp_alert} ${styles['bflp_alert--success']}`}>
                        {t('label.flushSuccess')}
                    </div>
                )}
                {flushStatus === 'error' && (
                    <div className={`${styles.bflp_alert} ${styles['bflp_alert--error']}`}>
                        {t('label.flushError')}
                    </div>
                )}
                <button
                    type="button"
                    className={styles.bflp_flushBtn}
                    disabled={flushing}
                    onClick={handleFlush}
                >
                    {flushing ? t('label.flushing') : t('label.flushCache')}
                </button>
            </div>
        </div>
    );
};

export default BruteForceLoginProtectionAdmin;
