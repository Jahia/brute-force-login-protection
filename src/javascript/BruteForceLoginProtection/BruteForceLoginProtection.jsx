import React, {useState} from 'react';
import {useMutation, useQuery} from '@apollo/client';
import {useTranslation} from 'react-i18next';
import {Button, Loader, Typography} from '@jahia/moonstone';
import styles from './BruteForceLoginProtection.scss';
import {FLUSH_CACHE, GET_SETTINGS, SAVE_SETTINGS} from './BruteForceLoginProtection.gql';

export const BruteForceLoginProtectionAdmin = () => {
    const {t} = useTranslation('brute-force-login-protection');
    const [saveStatus, setSaveStatus] = useState(null);
    const [flushStatus, setFlushStatus] = useState(null);
    const [validationError, setValidationError] = useState(null);

    const [formState, setFormState] = useState({
        activated: false,
        nbFailedLoginMax: 6,
        whitelistIps: '127.0.0.1/32,::1/128'
    });

    const {loading} = useQuery(GET_SETTINGS, {
        fetchPolicy: 'network-only',
        onCompleted: data => {
            if (data && data.bruteForceLoginProtectionSettings) {
                const s = data.bruteForceLoginProtectionSettings;
                setFormState({
                    activated: s.activated,
                    nbFailedLoginMax: s.nbFailedLoginMax,
                    whitelistIps: s.whitelistIps
                });
            }
        }
    });

    const [saveSettings, {loading: saving}] = useMutation(SAVE_SETTINGS);
    const [flushCache, {loading: flushing}] = useMutation(FLUSH_CACHE);

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
                    whitelistIps: formState.whitelistIps
                }
            });
            setSaveStatus(result.data && result.data.bruteForceLoginProtectionSaveSettings ? 'success' : 'error');
        } catch (err) {
            console.error('Failed to save settings:', err);
            setSaveStatus('error');
        }
    };

    const handleFlush = async () => {
        setFlushStatus(null);
        try {
            const result = await flushCache();
            setFlushStatus(result.data && result.data.bruteForceLoginProtectionFlushCache ? 'success' : 'error');
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
                    <label className={styles.bflp_toggle}>
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
                            nbFailedLoginMax: parseInt(e.target.value, 10) || 1
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
