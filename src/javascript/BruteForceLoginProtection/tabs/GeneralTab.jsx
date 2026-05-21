import React, {useRef, useState} from 'react';
import {useMutation, useQuery} from '@apollo/client';
import {useTranslation} from 'react-i18next';
import {Button, Loader} from '@jahia/moonstone';
import styles from '../BruteForceLoginProtection.scss';
import {GET_GLOBAL_SETTINGS, SAVE_GLOBAL_SETTINGS} from '../BruteForceLoginProtection.gql';
import {StatusAlerts} from './StatusAlerts';
import {useTransientStatus, validateWhitelist} from './useTransientStatus';

const DEFAULTS = {
    activated: false,
    whitelistIps: '127.0.0.1/32,::1/128',
    ignorePatterns: '',
    trustProxyHeader: false,
    recidiveFactor: 2.0,
    maxBanTimeSeconds: 604800,
    auditLogMaxEntries: 1000
};

export const GeneralTab = () => {
    const {t} = useTranslation('brute-force-login-protection');
    const [status, setStatus] = useTransientStatus();
    const [errors, setErrors] = useState({});
    const whitelistRef = useRef(null);
    const recidiveRef = useRef(null);
    const maxBanRef = useRef(null);
    const [form, setForm] = useState(DEFAULTS);

    const {loading} = useQuery(GET_GLOBAL_SETTINGS, {
        fetchPolicy: 'network-only',
        onCompleted: data => {
            const s = data?.bruteForceLoginProtectionGlobalSettings;
            if (s) {
                setForm({
                    activated: s.activated,
                    whitelistIps: s.whitelistIps ?? '',
                    ignorePatterns: (s.ignorePatterns || []).join('\n'),
                    trustProxyHeader: s.trustProxyHeader,
                    recidiveFactor: s.recidiveFactor ?? 2.0,
                    maxBanTimeSeconds: s.maxBanTimeSeconds ?? 604800,
                    auditLogMaxEntries: s.auditLogMaxEntries ?? 1000
                });
            }
        }
    });

    const [saveSettings, {loading: saving}] = useMutation(SAVE_GLOBAL_SETTINGS, {
        refetchQueries: ['GetGlobalSettings']
    });

    const validate = () => {
        const next = {};
        if (form.whitelistIps && !validateWhitelist(form.whitelistIps)) {
            next.whitelistIps = t('general.whitelistIpsInvalid');
        }

        if (!(Number(form.recidiveFactor) >= 1.0)) {
            next.recidiveFactor = t('general.recidiveFactorInvalid');
        }

        if (!(Number(form.maxBanTimeSeconds) > 0)) {
            next.maxBanTimeSeconds = t('general.maxBanTimeSecondsInvalid');
        }

        setErrors(next);
        if (next.whitelistIps) {
            whitelistRef.current?.focus();
        } else if (next.recidiveFactor) {
            recidiveRef.current?.focus();
        } else if (next.maxBanTimeSeconds) {
            maxBanRef.current?.focus();
        }

        return Object.keys(next).length === 0;
    };

    const handleSubmit = async e => {
        e.preventDefault();
        if (!validate()) {
            return;
        }

        try {
            const ignorePatterns = form.ignorePatterns
                .split('\n')
                .map(line => line.trim())
                .filter(Boolean);
            const result = await saveSettings({
                variables: {
                    activated: form.activated,
                    whitelistIps: form.whitelistIps,
                    ignorePatterns,
                    trustProxyHeader: form.trustProxyHeader,
                    recidiveFactor: Number(form.recidiveFactor),
                    maxBanTimeSeconds: Number.parseInt(form.maxBanTimeSeconds, 10),
                    auditLogMaxEntries: Number.parseInt(form.auditLogMaxEntries, 10)
                }
            });
            setStatus(result.data?.bruteForceLoginProtectionSaveGlobalSettings ? 'success' : 'error');
        } catch (err) {
            console.error('Failed to save global settings:', err);
            setStatus('error');
        }
    };

    if (loading) {
        return (
            <div className={styles.bflp_loading} aria-busy="true" aria-live="polite">
                <Loader size="big"/>
                <span className={styles.bflp_sr_only}>{t('label.loading')}</span>
            </div>
        );
    }

    return (
        <form onSubmit={handleSubmit} className={styles.bflp_tabPanel}>
            <div className={styles.bflp_sectionHeader}>
                <h3>{t('general.title')}</h3>
            </div>

            <div className={styles.bflp_form}>
                <div className={styles.bflp_fieldGroup}>
                    <span id="bflp-gen-activated-label" className={styles.bflp_label}>
                        {t('general.activated')}
                    </span>
                    <label className={styles.bflp_toggle}>
                        <input
                            type="checkbox"
                            aria-labelledby="bflp-gen-activated-label"
                            checked={form.activated}
                            onChange={e => setForm(prev => ({...prev, activated: e.target.checked}))}
                        />
                        <span className={styles.bflp_toggleSlider}/>
                    </label>
                </div>

                <div className={styles.bflp_fieldGroup}>
                    <label className={styles.bflp_label} htmlFor="bflp-gen-whitelist">
                        {t('general.whitelistIps')}
                    </label>
                    <p id="bflp-gen-whitelist-hint" className={styles.bflp_hint}>
                        {t('general.whitelistIpsHint')}
                    </p>
                    <textarea
                        ref={whitelistRef}
                        id="bflp-gen-whitelist"
                        className={styles.bflp_textarea}
                        rows={4}
                        autoComplete="off"
                        aria-invalid={errors.whitelistIps ? 'true' : undefined}
                        aria-describedby={`bflp-gen-whitelist-hint${errors.whitelistIps ? ' bflp-gen-whitelist-error' : ''}`}
                        value={form.whitelistIps}
                        onChange={e => setForm(prev => ({...prev, whitelistIps: e.target.value}))}
                    />
                    <p id="bflp-gen-whitelist-error" className={styles.bflp_fieldError} aria-live="polite" aria-atomic="true">
                        {errors.whitelistIps || ''}
                    </p>
                </div>

                <div className={styles.bflp_fieldGroup}>
                    <label className={styles.bflp_label} htmlFor="bflp-gen-ignore">
                        {t('general.ignorePatterns')}
                    </label>
                    <p id="bflp-gen-ignore-hint" className={styles.bflp_hint}>
                        {t('general.ignorePatternsHint')}
                    </p>
                    <textarea
                        id="bflp-gen-ignore"
                        className={styles.bflp_textarea}
                        rows={4}
                        autoComplete="off"
                        aria-describedby="bflp-gen-ignore-hint"
                        value={form.ignorePatterns}
                        onChange={e => setForm(prev => ({...prev, ignorePatterns: e.target.value}))}
                    />
                </div>

                <div className={styles.bflp_fieldGroup}>
                    <span id="bflp-gen-trust-label" className={styles.bflp_label}>
                        {t('general.trustProxyHeader')}
                    </span>
                    <p id="bflp-gen-trust-hint" className={styles.bflp_hint}>
                        {t('general.trustProxyHeaderHint')}
                    </p>
                    <label className={styles.bflp_toggle}>
                        <input
                            type="checkbox"
                            aria-labelledby="bflp-gen-trust-label"
                            aria-describedby="bflp-gen-trust-hint"
                            checked={form.trustProxyHeader}
                            onChange={e => setForm(prev => ({...prev, trustProxyHeader: e.target.checked}))}
                        />
                        <span className={styles.bflp_toggleSlider}/>
                    </label>
                </div>

                <div className={styles.bflp_fieldGroup}>
                    <label className={styles.bflp_label} htmlFor="bflp-gen-recidive">
                        {t('general.recidiveFactor')}
                    </label>
                    <p id="bflp-gen-recidive-hint" className={styles.bflp_hint}>
                        {t('general.recidiveFactorHint')}
                    </p>
                    <input
                        ref={recidiveRef}
                        type="number"
                        id="bflp-gen-recidive"
                        className={styles.bflp_input}
                        min="1"
                        step="0.1"
                        aria-invalid={errors.recidiveFactor ? 'true' : undefined}
                        aria-describedby={`bflp-gen-recidive-hint${errors.recidiveFactor ? ' bflp-gen-recidive-error' : ''}`}
                        value={form.recidiveFactor}
                        onChange={e => setForm(prev => ({...prev, recidiveFactor: e.target.value}))}
                    />
                    <p id="bflp-gen-recidive-error" className={styles.bflp_fieldError} aria-live="polite" aria-atomic="true">
                        {errors.recidiveFactor || ''}
                    </p>
                </div>

                <div className={styles.bflp_fieldGroup}>
                    <label className={styles.bflp_label} htmlFor="bflp-gen-maxban">
                        {t('general.maxBanTimeSeconds')}
                    </label>
                    <p id="bflp-gen-maxban-hint" className={styles.bflp_hint}>
                        {t('general.maxBanTimeSecondsHint')}
                    </p>
                    <input
                        ref={maxBanRef}
                        type="number"
                        id="bflp-gen-maxban"
                        className={styles.bflp_input}
                        min="1"
                        aria-invalid={errors.maxBanTimeSeconds ? 'true' : undefined}
                        aria-describedby={`bflp-gen-maxban-hint${errors.maxBanTimeSeconds ? ' bflp-gen-maxban-error' : ''}`}
                        value={form.maxBanTimeSeconds}
                        onChange={e => setForm(prev => ({...prev, maxBanTimeSeconds: e.target.value}))}
                    />
                    <p id="bflp-gen-maxban-error" className={styles.bflp_fieldError} aria-live="polite" aria-atomic="true">
                        {errors.maxBanTimeSeconds || ''}
                    </p>
                </div>

                <div className={styles.bflp_fieldGroup}>
                    <label className={styles.bflp_label} htmlFor="bflp-gen-auditmax">
                        {t('general.auditLogMaxEntries')}
                    </label>
                    <p id="bflp-gen-auditmax-hint" className={styles.bflp_hint}>
                        {t('general.auditLogMaxEntriesHint')}
                    </p>
                    <input
                        type="number"
                        id="bflp-gen-auditmax"
                        className={styles.bflp_input}
                        min="1"
                        aria-describedby="bflp-gen-auditmax-hint"
                        value={form.auditLogMaxEntries}
                        onChange={e => setForm(prev => ({...prev, auditLogMaxEntries: e.target.value}))}
                    />
                </div>
            </div>

            <div className={styles.bflp_actions}>
                <StatusAlerts status={status}/>
                <Button
                    type="submit"
                    label={saving ? t('label.saving') : t('label.save')}
                    variant="primary"
                    isDisabled={saving}
                />
            </div>
        </form>
    );
};

export default GeneralTab;
