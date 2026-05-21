import React, {useState} from 'react';
import {useMutation, useQuery} from '@apollo/client';
import {useTranslation} from 'react-i18next';
import {Button, Loader, Typography} from '@jahia/moonstone';
import styles from '../BruteForceLoginProtection.scss';
import {GET_BAN_ACTIONS, GET_GLOBAL_SETTINGS, SAVE_GLOBAL_SETTINGS} from '../BruteForceLoginProtection.gql';
import {StatusAlerts} from './StatusAlerts';
import {useTransientStatus} from './useTransientStatus';

export const IntegrationsTab = () => {
    const {t} = useTranslation('brute-force-login-protection');
    const [status, setStatus] = useTransientStatus();
    const [form, setForm] = useState({
        emailEnabled: false,
        emailRecipient: '',
        webhookUrl: '',
        webhookSecret: ''
    });
    const [secretConfigured, setSecretConfigured] = useState(false);

    const {loading} = useQuery(GET_GLOBAL_SETTINGS, {
        fetchPolicy: 'network-only',
        onCompleted: data => {
            const s = data?.bruteForceLoginProtectionGlobalSettings;
            if (s) {
                setForm({
                    emailEnabled: s.emailEnabled,
                    emailRecipient: s.emailRecipient || '',
                    webhookUrl: s.webhookUrl || '',
                    webhookSecret: ''
                });
                setSecretConfigured(Boolean(s.webhookSecretConfigured));
            }
        }
    });

    const {data: actionsData, loading: actionsLoading} = useQuery(GET_BAN_ACTIONS, {fetchPolicy: 'network-only'});

    const [saveSettings, {loading: saving}] = useMutation(SAVE_GLOBAL_SETTINGS, {
        refetchQueries: ['GetGlobalSettings']
    });

    const handleSubmit = async e => {
        e.preventDefault();
        try {
            // Null = leave unchanged for webhookSecret if input is blank
            const variables = {
                emailEnabled: form.emailEnabled,
                emailRecipient: form.emailRecipient,
                webhookUrl: form.webhookUrl
            };
            if (form.webhookSecret) {
                variables.webhookSecret = form.webhookSecret;
            }

            const r = await saveSettings({variables});
            if (r.data?.bruteForceLoginProtectionSaveGlobalSettings) {
                setStatus('success');
                setForm(prev => ({...prev, webhookSecret: ''}));
            } else {
                setStatus('error');
            }
        } catch (err) {
            console.error('Failed to save integrations:', err);
            setStatus('error');
        }
    };

    const handleClearSecret = async () => {
        // eslint-disable-next-line no-alert
        if (!window.confirm(t('integrations.clearSecret') + '?')) {
            return;
        }

        try {
            const r = await saveSettings({variables: {webhookSecret: ''}});
            if (r.data?.bruteForceLoginProtectionSaveGlobalSettings) {
                setStatus('success');
                setSecretConfigured(false);
            } else {
                setStatus('error');
            }
        } catch (err) {
            console.error('Failed to clear webhook secret:', err);
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

    const actions = actionsData?.bruteForceLoginProtectionBanActions || [];

    return (
        <form onSubmit={handleSubmit} className={styles.bflp_tabPanel}>
            <div className={styles.bflp_subSection}>
                <h3>{t('integrations.emailTitle')}</h3>
                <div className={styles.bflp_fieldGroup}>
                    <span id="bflp-int-email-label" className={styles.bflp_label}>{t('integrations.emailEnabled')}</span>
                    <label className={styles.bflp_toggle}>
                        <input
                            type="checkbox"
                            aria-labelledby="bflp-int-email-label"
                            checked={form.emailEnabled}
                            onChange={e => setForm(prev => ({...prev, emailEnabled: e.target.checked}))}
                        />
                        <span className={styles.bflp_toggleSlider}/>
                    </label>
                </div>
                <div className={styles.bflp_fieldGroup}>
                    <label className={styles.bflp_label} htmlFor="bflp-int-email-recipient">{t('integrations.emailRecipient')}</label>
                    <input
                        id="bflp-int-email-recipient"
                        type="email"
                        className={`${styles.bflp_input} ${styles['bflp_input--wide']}`}
                        autoComplete="off"
                        aria-describedby="bflp-int-email-hint"
                        value={form.emailRecipient}
                        onChange={e => setForm(prev => ({...prev, emailRecipient: e.target.value}))}
                    />
                    <p id="bflp-int-email-hint" className={styles.bflp_hint}>{t('integrations.emailRecipientHint')}</p>
                </div>
            </div>

            <div className={styles.bflp_subSection}>
                <h3>{t('integrations.webhookTitle')}</h3>
                <div className={styles.bflp_fieldGroup}>
                    <label className={styles.bflp_label} htmlFor="bflp-int-webhook-url">{t('integrations.webhookUrl')}</label>
                    <input
                        id="bflp-int-webhook-url"
                        type="url"
                        className={`${styles.bflp_input} ${styles['bflp_input--wide']}`}
                        autoComplete="off"
                        aria-describedby="bflp-int-webhook-url-hint"
                        value={form.webhookUrl}
                        onChange={e => setForm(prev => ({...prev, webhookUrl: e.target.value}))}
                    />
                    <p id="bflp-int-webhook-url-hint" className={styles.bflp_hint}>{t('integrations.webhookUrlHint')}</p>
                </div>
                <div className={styles.bflp_fieldGroup}>
                    <label className={styles.bflp_label} htmlFor="bflp-int-webhook-secret">{t('integrations.webhookSecret')}</label>
                    <input
                        id="bflp-int-webhook-secret"
                        type="password"
                        className={`${styles.bflp_input} ${styles['bflp_input--wide']}`}
                        autoComplete="new-password"
                        aria-describedby="bflp-int-webhook-secret-hint"
                        value={form.webhookSecret}
                        onChange={e => setForm(prev => ({...prev, webhookSecret: e.target.value}))}
                    />
                    <p id="bflp-int-webhook-secret-hint" className={styles.bflp_hint}>{t('integrations.webhookSecretHint')}</p>
                    <p
                        className={`${styles.bflp_secretStatus} ${secretConfigured ? '' : styles['bflp_secretStatus--missing']}`}
                        aria-live="polite"
                    >
                        {secretConfigured ? t('integrations.webhookSecretConfigured') : t('integrations.webhookSecretNotConfigured')}
                    </p>
                    {secretConfigured && (
                        <div className={styles.bflp_inlineActions}>
                            <button
                                type="button"
                                className={styles.bflp_unbanBtn}
                                disabled={saving}
                                onClick={handleClearSecret}
                            >
                                {t('integrations.clearSecret')}
                            </button>
                        </div>
                    )}
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

            <div className={styles.bflp_subSection}>
                <h3>{t('integrations.banActionsTitle')}</h3>
                {actionsLoading && (
                    <div className={styles.bflp_loading} aria-busy="true" aria-live="polite">
                        <Loader size="big"/>
                        <span className={styles.bflp_sr_only}>{t('label.loading')}</span>
                    </div>
                )}
                {!actionsLoading && actions.length === 0 && (
                    <Typography className={styles.bflp_emptyState}>{t('integrations.noBanActions')}</Typography>
                )}
                {!actionsLoading && actions.length > 0 && (
                    <table className={styles.bflp_table}>
                        <thead>
                            <tr>
                                <th scope="col">{t('integrations.colName')}</th>
                                <th scope="col">{t('integrations.colPriority')}</th>
                                <th scope="col">{t('integrations.colClass')}</th>
                            </tr>
                        </thead>
                        <tbody>
                            {actions.map(a => (
                                <tr key={a.className}>
                                    <td>{a.name}</td>
                                    <td>{a.priority}</td>
                                    <td className={styles.bflp_ipCell}>{a.className}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>
        </form>
    );
};

export default IntegrationsTab;
