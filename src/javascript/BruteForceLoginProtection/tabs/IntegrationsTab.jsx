import React, {useState} from 'react';
import {useMutation, useQuery} from '@apollo/client';
import {useTranslation} from 'react-i18next';
import {Button, Loader, Typography} from '@jahia/moonstone';
import styles from '../BruteForceLoginProtection.scss';
import {GET_BAN_ACTIONS, GET_GLOBAL_SETTINGS, SAVE_GLOBAL_SETTINGS, TEST_EMAIL, TEST_WEBHOOK} from '../BruteForceLoginProtection.gql';
import {ConfirmDialog} from '../ConfirmDialog';
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
    const [confirmClearSecret, setConfirmClearSecret] = useState(false);

    // F-31: i18n for test result messages — pre-rendered live region containers
    const [emailTestResult, setEmailTestResult] = useState(null);
    const [webhookTestResult, setWebhookTestResult] = useState(null);

    const {data, loading} = useQuery(GET_GLOBAL_SETTINGS, {
        fetchPolicy: 'network-only',
        onCompleted: data => {
            const s = data?.bruteForceLoginProtection?.globalSettings;
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

    const [testEmail, {loading: testingEmail}] = useMutation(TEST_EMAIL);
    const [testWebhook, {loading: testingWebhook}] = useMutation(TEST_WEBHOOK);

    const handleTestEmail = async () => {
        setEmailTestResult(null);
        try {
            const r = await testEmail();
            // F-31: use t() instead of hardcoded 'No response'
            setEmailTestResult(r.data?.bruteForceLoginProtection?.testEmail || {success: false, message: t('integrations.noResponse')});
        } catch (err) {
            // F-31: use t() instead of hardcoded 'Request failed'
            setEmailTestResult({success: false, message: err.message || t('integrations.requestFailed')});
        }
    };

    const handleTestWebhook = async () => {
        setWebhookTestResult(null);
        try {
            const r = await testWebhook();
            setWebhookTestResult(r.data?.bruteForceLoginProtection?.testWebhook || {success: false, message: t('integrations.noResponse')});
        } catch (err) {
            setWebhookTestResult({success: false, message: err.message || t('integrations.requestFailed')});
        }
    };

    // F-01/F-02: build the full set of current global settings so that saving
    // the integration fields never resets unrelated settings to null. Shared by
    // both save paths (handleSubmit + handleClearSecretConfirm) so they stay
    // identical. trustedProxyCidrs is included so it is not dropped on save.
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
            emailEnabled: form.emailEnabled,
            emailRecipient: form.emailRecipient,
            webhookUrl: form.webhookUrl
        };
    };

    const handleSubmit = async e => {
        e.preventDefault();
        try {
            const variables = buildBaseSettings();
            if (form.webhookSecret) {
                variables.webhookSecret = form.webhookSecret;
            }

            const r = await saveSettings({variables});
            if (r.data?.bruteForceLoginProtection?.saveGlobalSettings) {
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

    // F-19/F-30: replaced window.confirm with ConfirmDialog
    const handleClearSecretRequest = () => {
        setConfirmClearSecret(true);
    };

    const handleClearSecretConfirm = async () => {
        setConfirmClearSecret(false);
        try {
            // F-01: merge ALL current settings (same shape as handleSubmit) and
            // only override webhookSecret with '' to clear it — sending just
            // webhookSecret would clobber every other setting to undefined.
            const variables = {...buildBaseSettings(), webhookSecret: ''};
            const r = await saveSettings({variables});
            if (r.data?.bruteForceLoginProtection?.saveGlobalSettings) {
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

    const handleClearSecretCancel = () => {
        setConfirmClearSecret(false);
    };

    if (loading) {
        return (
            <div aria-busy="true" aria-live="polite" className={styles.bflp_loading}>
                <Loader size="big"/>
                <span className={styles.bflp_sr_only}>{t('label.loading')}</span>
            </div>
        );
    }

    const actions = actionsData?.bruteForceLoginProtection?.banActions || [];

    return (
        <div className={styles.bflp_tabPanel}>
            <form aria-label={t('integrations.formLabel')} onSubmit={handleSubmit}>
                <div className={styles.bflp_subSection}>
                    <h3>{t('integrations.emailTitle')}</h3>
                    <div className={styles.bflp_fieldGroup}>
                        <span className={styles.bflp_label} id="bflp-int-email-label">{t('integrations.emailEnabled')}</span>
                        <p className={styles.bflp_hint} id="bflp-int-email-enabled-hint">{t('integrations.emailEnabledHint')}</p>
                        <label className={styles.bflp_toggle}>
                            <input
                            aria-describedby="bflp-int-email-enabled-hint"
                            aria-labelledby="bflp-int-email-label"
                            checked={form.emailEnabled}
                            type="checkbox"
                            onChange={e => setForm(prev => ({...prev, emailEnabled: e.target.checked}))}
                        />
                            <span className={styles.bflp_toggleSlider}/>
                        </label>
                    </div>
                    <div className={styles.bflp_fieldGroup}>
                        <label className={styles.bflp_label} htmlFor="bflp-int-email-recipient">{t('integrations.emailRecipient')}</label>
                        <input
                        aria-describedby="bflp-int-email-hint"
                        autoComplete="off"
                        className={`${styles.bflp_input} ${styles['bflp_input--wide']}`}
                        id="bflp-int-email-recipient"
                        type="email"
                        value={form.emailRecipient}
                        onChange={e => setForm(prev => ({...prev, emailRecipient: e.target.value}))}
                    />
                        {/* F-06: hint is now after the input and correctly wired */}
                        <p className={styles.bflp_hint} id="bflp-int-email-hint">{t('integrations.emailRecipientHint')}</p>
                    </div>
                    <div className={styles.bflp_inlineActions}>
                        <button
                        aria-describedby="bflp-int-test-email-hint"
                        className={styles.bflp_tableActionBtn}
                        disabled={testingEmail}
                        type="button"
                        onClick={handleTestEmail}
                        >
                            {testingEmail ? t('integrations.testEmailSending') : t('integrations.testEmail')}
                        </button>
                        <p className={styles.bflp_hint} id="bflp-int-test-email-hint">{t('integrations.testEmailHint')}</p>
                    </div>
                    {/* F-22/F-25/F-26: pre-rendered live region — always present, content conditional */}
                    <div
                    aria-atomic="true"
                    aria-live="polite"
                    role="status"
                    >
                        {emailTestResult && (
                        <div className={`${styles.bflp_alert} ${emailTestResult.success ? styles['bflp_alert--success'] : styles['bflp_alert--error']}`}>
                            {emailTestResult.message}
                        </div>
                    )}
                    </div>
                </div>

                <div className={styles.bflp_subSection}>
                    <h3>{t('integrations.webhookTitle')}</h3>
                    <div className={styles.bflp_fieldGroup}>
                        <label className={styles.bflp_label} htmlFor="bflp-int-webhook-url">{t('integrations.webhookUrl')}</label>
                        <input
                        aria-describedby="bflp-int-webhook-url-hint"
                        autoComplete="off"
                        className={`${styles.bflp_input} ${styles['bflp_input--wide']}`}
                        id="bflp-int-webhook-url"
                        type="url"
                        value={form.webhookUrl}
                        onChange={e => setForm(prev => ({...prev, webhookUrl: e.target.value}))}
                    />
                        <p className={styles.bflp_hint} id="bflp-int-webhook-url-hint">{t('integrations.webhookUrlHint')}</p>
                    </div>
                    <div className={styles.bflp_fieldGroup}>
                        <label className={styles.bflp_label} htmlFor="bflp-int-webhook-secret">{t('integrations.webhookSecret')}</label>
                        <input
                        aria-describedby="bflp-int-webhook-secret-hint"
                        autoComplete="new-password"
                        className={`${styles.bflp_input} ${styles['bflp_input--wide']}`}
                        id="bflp-int-webhook-secret"
                        type="password"
                        value={form.webhookSecret}
                        onChange={e => setForm(prev => ({...prev, webhookSecret: e.target.value}))}
                    />
                        <p className={styles.bflp_hint} id="bflp-int-webhook-secret-hint">{t('integrations.webhookSecretHint')}</p>
                        <p
                        aria-live="polite"
                        className={`${styles.bflp_secretStatus} ${secretConfigured ? '' : styles['bflp_secretStatus--missing']}`}
                        >
                            {secretConfigured ? t('integrations.webhookSecretConfigured') : t('integrations.webhookSecretNotConfigured')}
                        </p>
                        {secretConfigured && (
                        <div className={styles.bflp_inlineActions}>
                            <button
                                className={styles.bflp_tableActionBtn}
                                disabled={saving}
                                type="button"
                                onClick={handleClearSecretRequest}
                            >
                                {t('integrations.clearSecret')}
                            </button>
                        </div>
                    )}
                    </div>
                    <div className={styles.bflp_inlineActions}>
                        <button
                        aria-describedby="bflp-int-test-webhook-hint"
                        className={styles.bflp_tableActionBtn}
                        disabled={testingWebhook}
                        type="button"
                        onClick={handleTestWebhook}
                        >
                            {testingWebhook ? t('integrations.testWebhookSending') : t('integrations.testWebhook')}
                        </button>
                        <p className={styles.bflp_hint} id="bflp-int-test-webhook-hint">{t('integrations.testWebhookHint')}</p>
                    </div>
                    {/* F-22/F-25/F-26: pre-rendered live region — always present, content conditional */}
                    <div
                    aria-atomic="true"
                    aria-live="polite"
                    role="status"
                    >
                        {webhookTestResult && (
                        <div className={`${styles.bflp_alert} ${webhookTestResult.success ? styles['bflp_alert--success'] : styles['bflp_alert--error']}`}>
                            {webhookTestResult.message}
                        </div>
                    )}
                    </div>
                </div>

                <div className={styles.bflp_actions}>
                    {/* F-22/F-25/F-26: pre-rendered live regions */}
                    <StatusAlerts status={status}/>
                    <Button
                    isDisabled={saving}
                    label={saving ? t('label.saving') : t('label.save')}
                    type="submit"
                    variant="primary"
                />
                </div>
            </form>

            {/* F-02: read-only informational table lives outside the form */}
            <div className={styles.bflp_subSection}>
                <h3>{t('integrations.banActionsTitle')}</h3>
                {actionsLoading && (
                    <div aria-busy="true" aria-live="polite" className={styles.bflp_loading}>
                        <Loader size="big"/>
                        <span className={styles.bflp_sr_only}>{t('label.loading')}</span>
                    </div>
                )}
                {!actionsLoading && actions.length === 0 && (
                    <Typography className={styles.bflp_emptyState}>{t('integrations.noBanActions')}</Typography>
                )}
                {!actionsLoading && actions.length > 0 && (
                    <table className={styles.bflp_table}>
                        {/* F-11: table caption */}
                        <caption className={styles.bflp_tableCaption}>{t('integrations.banActionsTableCaption')}</caption>
                        <thead>
                            <tr>
                                {/* F-12: aria-sort on Priority (pre-sorted ascending) */}
                                <th scope="col">{t('integrations.colName')}</th>
                                <th aria-sort="ascending" scope="col">{t('integrations.colPriority')}</th>
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

            {/* F-19/F-30: accessible confirm dialog for clear secret */}
            <ConfirmDialog
                isOpen={confirmClearSecret}
                message={t('integrations.clearSecretConfirm')}
                onCancel={handleClearSecretCancel}
                onConfirm={handleClearSecretConfirm}
            />
        </div>
    );
};

export default IntegrationsTab;
