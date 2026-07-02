import React, {useState} from 'react';
import {useMutation, useQuery} from '@apollo/client';
import {useTranslation} from 'react-i18next';
import {Button, Loader} from '@jahia/moonstone';
import styles from '../BruteForceLoginProtection.scss';
import {GET_BLOCKLIST_STATUS, GET_GLOBAL_SETTINGS, REFRESH_TOR_BLOCKLIST, SAVE_GLOBAL_SETTINGS} from '../BruteForceLoginProtection.gql';
import {StatusAlerts} from './StatusAlerts';
import {useTransientStatus, formatDuration, formatEpoch} from './useTransientStatus';

export const BlocklistTab = () => {
    const {t} = useTranslation('brute-force-login-protection');
    const [status, setStatus] = useTransientStatus();
    const [form, setForm] = useState({
        blocklistIps: '',
        torBlocklistEnabled: false,
        torBlocklistUrl: '',
        torBlocklistRefreshSeconds: 3600
    });
    const [refreshResult, setRefreshResult] = useState(null);

    const {data, loading} = useQuery(GET_GLOBAL_SETTINGS, {
        fetchPolicy: 'network-only',
        onCompleted: data => {
            const s = data?.bruteForceLoginProtection?.globalSettings;
            if (s) {
                setForm({
                    // Stored comma-separated; edited one-per-line for readability
                    blocklistIps: (s.blocklistIps || '').split(',').map(v => v.trim()).filter(Boolean)
                        .join('\n'),
                    torBlocklistEnabled: s.torBlocklistEnabled,
                    torBlocklistUrl: s.torBlocklistUrl || '',
                    torBlocklistRefreshSeconds: s.torBlocklistRefreshSeconds || 3600
                });
            }
        }
    });

    const {data: statusData, refetch: refetchStatus} = useQuery(GET_BLOCKLIST_STATUS, {
        fetchPolicy: 'network-only',
        pollInterval: 30000
    });

    const [saveSettings, {loading: saving}] = useMutation(SAVE_GLOBAL_SETTINGS, {
        refetchQueries: ['GetGlobalSettings', 'GetBlocklistStatus']
    });

    const [refreshTor, {loading: refreshing}] = useMutation(REFRESH_TOR_BLOCKLIST);

    // Same F-01/F-02 pattern as IntegrationsTab: send every current global setting so a save
    // from this tab never resets unrelated fields (the backend treats null as "unchanged",
    // but the UI keeps the full snapshot explicit).
    const buildBaseSettings = () => {
        const current = data?.bruteForceLoginProtection?.globalSettings || {};
        return {
            activated: current.activated,
            whitelistIps: current.whitelistIps ?? '',
            ignorePatterns: current.ignorePatterns || [],
            trustProxyHeader: current.trustProxyHeader,
            trustedProxyCidrs: current.trustedProxyCidrs || [],
            recidiveFactor: current.recidiveFactor,
            maxBanTimeSeconds: current.maxBanTimeSeconds,
            auditLogMaxEntries: current.auditLogMaxEntries,
            emailEnabled: current.emailEnabled,
            emailRecipient: current.emailRecipient ?? '',
            webhookUrl: current.webhookUrl ?? '',
            blocklistIps: form.blocklistIps.split(/[\n,]/).map(v => v.trim()).filter(Boolean)
                .join(','),
            torBlocklistEnabled: form.torBlocklistEnabled,
            torBlocklistUrl: form.torBlocklistUrl,
            torBlocklistRefreshSeconds: Number(form.torBlocklistRefreshSeconds) || 3600
        };
    };

    const handleSubmit = async e => {
        e.preventDefault();
        try {
            const r = await saveSettings({variables: buildBaseSettings()});
            setStatus(r.data?.bruteForceLoginProtection?.saveGlobalSettings ? 'success' : 'error');
        } catch (err) {
            console.error('Failed to save blocklist settings:', err);
            setStatus('error');
        }
    };

    const handleRefreshNow = async () => {
        setRefreshResult(null);
        try {
            const r = await refreshTor();
            setRefreshResult(r.data?.bruteForceLoginProtection?.refreshTorBlocklist || {success: false, message: t('blocklist.noResponse')});
        } catch (err) {
            setRefreshResult({success: false, message: err.message || t('blocklist.requestFailed')});
        }

        refetchStatus();
    };

    if (loading) {
        return (
            <div aria-busy="true" aria-live="polite" className={styles.bflp_loading}>
                <Loader size="big"/>
                <span className={styles.bflp_sr_only}>{t('label.loading')}</span>
            </div>
        );
    }

    const live = statusData?.bruteForceLoginProtection?.blocklistStatus;

    return (
        <div className={styles.bflp_tabPanel}>
            <form aria-label={t('blocklist.formLabel')} onSubmit={handleSubmit}>
                <div className={styles.bflp_subSection}>
                    <h3>{t('blocklist.staticTitle')}</h3>
                    <div className={styles.bflp_fieldGroup}>
                        <label className={styles.bflp_label} htmlFor="bflp-blk-static">{t('blocklist.staticLabel')}</label>
                        <textarea
                            aria-describedby="bflp-blk-static-hint"
                            autoComplete="off"
                            className={`${styles.bflp_input} ${styles['bflp_input--wide']}`}
                            id="bflp-blk-static"
                            rows={6}
                            spellCheck="false"
                            value={form.blocklistIps}
                            onChange={e => setForm(prev => ({...prev, blocklistIps: e.target.value}))}
                        />
                        <p className={styles.bflp_hint} id="bflp-blk-static-hint">{t('blocklist.staticHint')}</p>
                    </div>
                </div>

                <div className={styles.bflp_subSection}>
                    <h3>{t('blocklist.torTitle')}</h3>
                    <div className={styles.bflp_fieldGroup}>
                        <span className={styles.bflp_label} id="bflp-blk-tor-enabled-label">{t('blocklist.torEnabled')}</span>
                        <p className={styles.bflp_hint} id="bflp-blk-tor-enabled-hint">{t('blocklist.torEnabledHint')}</p>
                        <label className={styles.bflp_toggle}>
                            <input
                                aria-describedby="bflp-blk-tor-enabled-hint"
                                aria-labelledby="bflp-blk-tor-enabled-label"
                                checked={form.torBlocklistEnabled}
                                type="checkbox"
                                onChange={e => setForm(prev => ({...prev, torBlocklistEnabled: e.target.checked}))}
                            />
                            <span className={styles.bflp_toggleSlider}/>
                        </label>
                    </div>
                    <div className={styles.bflp_fieldGroup}>
                        <label className={styles.bflp_label} htmlFor="bflp-blk-tor-url">{t('blocklist.torUrl')}</label>
                        <input
                            aria-describedby="bflp-blk-tor-url-hint"
                            autoComplete="off"
                            className={`${styles.bflp_input} ${styles['bflp_input--wide']}`}
                            id="bflp-blk-tor-url"
                            type="url"
                            value={form.torBlocklistUrl}
                            onChange={e => setForm(prev => ({...prev, torBlocklistUrl: e.target.value}))}
                        />
                        <p className={styles.bflp_hint} id="bflp-blk-tor-url-hint">{t('blocklist.torUrlHint')}</p>
                    </div>
                    <div className={styles.bflp_fieldGroup}>
                        <label className={styles.bflp_label} htmlFor="bflp-blk-tor-refresh">{t('blocklist.torRefresh')}</label>
                        <input
                            aria-describedby="bflp-blk-tor-refresh-hint"
                            className={styles.bflp_input}
                            id="bflp-blk-tor-refresh"
                            max={604800}
                            min={300}
                            type="number"
                            value={form.torBlocklistRefreshSeconds}
                            onChange={e => setForm(prev => ({...prev, torBlocklistRefreshSeconds: e.target.value}))}
                        />
                        <p className={styles.bflp_hint} id="bflp-blk-tor-refresh-hint">{t('blocklist.torRefreshHint')}</p>
                    </div>
                </div>

                <div className={styles.bflp_actions}>
                    <StatusAlerts status={status}/>
                    <Button
                        isDisabled={saving}
                        label={saving ? t('label.saving') : t('label.save')}
                        type="submit"
                        variant="primary"
                    />
                </div>
            </form>

            {/* Live per-node status — read-only, outside the form */}
            <div className={styles.bflp_subSection}>
                <h3>{t('blocklist.statusTitle')}</h3>
                <div aria-atomic="true" aria-live="polite" role="status">
                    {live && (
                        <>
                            <p className={styles.bflp_hint}>
                                {t('blocklist.statusStaticCount', {count: live.staticEntryCount})}
                            </p>
                            <p className={styles.bflp_hint}>
                                {live.torEnabled ?
                                    t('blocklist.statusTorCount', {count: live.torEntryCount}) :
                                    t('blocklist.statusTorDisabled')}
                            </p>
                            <p className={styles.bflp_hint}>
                                {live.torLastFetchTime ?
                                    t('blocklist.statusLastFetch', {
                                        time: formatEpoch(live.torLastFetchTime),
                                        age: formatDuration(live.torListAgeSeconds)
                                    }) :
                                    t('blocklist.statusNeverFetched')}
                            </p>
                            {live.torLastError && (
                                <div className={`${styles.bflp_alert} ${styles['bflp_alert--error']}`}>
                                    {t('blocklist.statusLastError', {error: live.torLastError})}
                                </div>
                            )}
                        </>
                    )}
                </div>
                <div className={styles.bflp_inlineActions}>
                    <button
                        aria-describedby="bflp-blk-fetch-now-hint"
                        className={styles.bflp_tableActionBtn}
                        disabled={refreshing}
                        type="button"
                        onClick={handleRefreshNow}
                    >
                        {refreshing ? t('blocklist.fetching') : t('blocklist.fetchNow')}
                    </button>
                    <p className={styles.bflp_hint} id="bflp-blk-fetch-now-hint">{t('blocklist.fetchNowHint')}</p>
                </div>
                <div aria-atomic="true" aria-live="polite" role="status">
                    {refreshResult && (
                        <div className={`${styles.bflp_alert} ${refreshResult.success ? styles['bflp_alert--success'] : styles['bflp_alert--error']}`}>
                            {refreshResult.message}
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

export default BlocklistTab;
