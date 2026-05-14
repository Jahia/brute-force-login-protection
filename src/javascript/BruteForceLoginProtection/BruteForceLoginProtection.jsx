import React, {useRef, useState} from 'react';
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
    const whitelistRef = useRef(null);

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
            // C-3: move focus to the invalid field so AT reads the error via aria-describedby
            whitelistRef.current?.focus();
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
            // Mi-2 / M-11: aria-busy + visually-hidden text announces loading state to AT
            <div className={styles.bflp_loading} aria-busy="true" aria-live="polite">
                <Loader size="big"/>
                <span className={styles.bflp_sr_only}>{t('label.loading')}</span>
            </div>
        );
    }

    const trackedRows = trackedData?.bruteForceLoginProtectionTrackedIps;
    let trackedContent;
    if (trackedLoading && !trackedRows) {
        trackedContent = (
            <div className={styles.bflp_loading} aria-busy="true" aria-live="polite">
                <Loader size="big"/>
                <span className={styles.bflp_sr_only}>{t('label.loading')}</span>
            </div>
        );
    } else if (trackedRows?.length > 0) {
        trackedContent = (
            // M-3: aria-labelledby connects table to section heading
            <table className={styles.bflp_table} aria-labelledby="bflp-tracked-heading">
                <thead>
                    <tr>
                        {/* M-2: scope="col" ensures AT maps headers to data cells */}
                        <th scope="col">{t('label.colIp')}</th>
                        <th scope="col">{t('label.colFailedLogins')}</th>
                        <th scope="col">{t('label.colStatus')}</th>
                        <th scope="col">{t('label.colActions')}</th>
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
                                {/* M-4: aria-label includes IP so each button is distinguishable */}
                                <button
                                    type="button"
                                    className={styles.bflp_unblockBtn}
                                    aria-label={`${t('label.unblock')} ${row.ip}`}
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

            {/* Mi-1: <form> wrapper enables Enter-key submission and AT form navigation */}
            <form onSubmit={e => { e.preventDefault(); handleSave(); }}>
                <div className={styles.bflp_form}>
                    <div className={styles.bflp_fieldGroup}>
                        {/* C-2: label wraps both the visible text and the toggle so it has text content
                            and provides implicit labeling — fixes "empty label" and "no text in label" checks */}
                        <label className={styles.bflp_toggleLabel}>
                            <span className={styles.bflp_label}>{t('label.serviceStatus')}</span>
                            <span className={styles.bflp_toggle}>
                                <input
                                    type="checkbox"
                                    checked={formState.activated}
                                    onChange={e => setFormState(prev => ({...prev, activated: e.target.checked}))}
                                />
                                <span className={styles.bflp_toggleSlider}/>
                            </span>
                        </label>
                    </div>

                    <div className={styles.bflp_fieldGroup}>
                        <label className={styles.bflp_label} htmlFor="bflp-max">
                            {t('label.nbFailedLoginMax')}
                        </label>
                        {/* Mi-4: aria-describedby links input to its range hint */}
                        <input
                            type="number"
                            id="bflp-max"
                            className={styles.bflp_input}
                            min="1"
                            aria-describedby="bflp-max-hint"
                            value={formState.nbFailedLoginMax}
                            onChange={e => setFormState(prev => ({
                                ...prev,
                                nbFailedLoginMax: Number.parseInt(e.target.value, 10) || 1
                            }))}
                        />
                        <p id="bflp-max-hint" className={styles.bflp_hint}>{t('label.nbFailedLoginMaxHint')}</p>
                    </div>

                    <div className={styles.bflp_fieldGroup}>
                        <label className={styles.bflp_label} htmlFor="bflp-whitelist">
                            {t('label.whitelistIps')}
                            {/* M-5: aria-hidden hides decorative ⓘ glyph from AT */}
                            <span aria-hidden="true" className={styles.bflp_tooltip}>ⓘ</span>
                        </label>
                        {/* M-5: visible hint replaces hover-only tooltip — keyboard accessible */}
                        <p id="bflp-whitelist-hint" className={styles.bflp_hint}>{t('label.whitelistIpsTooltip')}</p>
                        {/* C-3: aria-describedby chains hint + error; ref enables focus on validation failure */}
                        <textarea
                            id="bflp-whitelist"
                            ref={whitelistRef}
                            className={styles.bflp_textarea}
                            rows={6}
                            aria-describedby="bflp-whitelist-hint bflp-whitelist-error"
                            value={formState.whitelistIps}
                            onChange={e => setFormState(prev => ({...prev, whitelistIps: e.target.value}))}
                        />
                        {/* C-3: always-present error container — content change is read by AT when focus is on field */}
                        <p id="bflp-whitelist-error" className={styles.bflp_fieldError} aria-atomic="true">
                            {validationError || ''}
                        </p>
                    </div>

                    <div className={styles.bflp_fieldGroup}>
                        <label className={styles.bflp_label} htmlFor="bflp-tti">
                            {t('label.timeToIdle')}
                            {/* M-5: aria-hidden hides decorative ⓘ glyph from AT */}
                            <span aria-hidden="true" className={styles.bflp_tooltip}>ⓘ</span>
                        </label>
                        {/* Mi-4: aria-describedby links input to its range hint */}
                        <input
                            type="number"
                            id="bflp-tti"
                            className={styles.bflp_input}
                            min="1"
                            aria-describedby="bflp-tti-hint"
                            value={formState.timeToIdle}
                            onChange={e => setFormState(prev => ({
                                ...prev,
                                timeToIdle: Number.parseInt(e.target.value, 10) || 3600
                            }))}
                        />
                        {/* M-5: visible hint replaces hover-only tooltip — keyboard accessible */}
                        <p id="bflp-tti-hint" className={styles.bflp_hint}>{t('label.timeToIdleTooltip')}</p>
                    </div>
                </div>

                <div className={styles.bflp_actions}>
                    {/* C-1: always-present live regions — AT announces status changes even when React mounts/unmounts inner content */}
                    <div role="alert" aria-live="assertive" aria-atomic="true">
                        {saveStatus === 'error' && (
                            <div className={`${styles.bflp_alert} ${styles['bflp_alert--error']}`}>
                                {t('label.saveError')}
                            </div>
                        )}
                    </div>
                    <div role="status" aria-live="polite" aria-atomic="true">
                        {saveStatus === 'success' && (
                            <div className={`${styles.bflp_alert} ${styles['bflp_alert--success']}`}>
                                {t('label.saveSuccess')}
                            </div>
                        )}
                    </div>
                    <Button
                        label={t('label.save')}
                        variant="primary"
                        isDisabled={saving}
                        onClick={handleSave}
                    />
                </div>
            </form>

            {/* Mi-3: aria-busy on section container signals loading state to AT */}
            <div className={styles.bflp_trackedSection} aria-busy={trackedLoading}>
                <div className={styles.bflp_sectionHeader}>
                    {/* M-3: id referenced by table's aria-labelledby */}
                    <h3 id="bflp-tracked-heading">{t('label.trackedIpsTitle')}</h3>
                    <button
                        type="button"
                        className={styles.bflp_refreshBtn}
                        aria-busy={trackedLoading}
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
                {/* C-1: always-present live regions for flush operation feedback */}
                <div role="alert" aria-live="assertive" aria-atomic="true">
                    {flushStatus === 'error' && (
                        <div className={`${styles.bflp_alert} ${styles['bflp_alert--error']}`}>
                            {t('label.flushError')}
                        </div>
                    )}
                </div>
                <div role="status" aria-live="polite" aria-atomic="true">
                    {flushStatus === 'success' && (
                        <div className={`${styles.bflp_alert} ${styles['bflp_alert--success']}`}>
                            {t('label.flushSuccess')}
                        </div>
                    )}
                </div>
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
