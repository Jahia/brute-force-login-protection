import React, {useState} from 'react';
import {useMutation, useQuery} from '@apollo/client';
import {useTranslation} from 'react-i18next';
import {Button, Loader, Typography} from '@jahia/moonstone';
import styles from '../BruteForceLoginProtection.scss';
import {DELETE_JAIL, GET_JAILS, SAVE_JAIL} from '../BruteForceLoginProtection.gql';
import {StatusAlerts} from './StatusAlerts';
import {useTransientStatus} from './useTransientStatus';

const EMPTY_FORM = {
    name: '',
    enabled: true,
    maxRetry: 6,
    findTimeSeconds: 600,
    banTimeSeconds: 3600,
    isNew: true
};

export const JailsTab = () => {
    const {t} = useTranslation('brute-force-login-protection');
    const [status, setStatus] = useTransientStatus();
    const [editingForm, setEditingForm] = useState(null);

    const {data, loading} = useQuery(GET_JAILS, {fetchPolicy: 'network-only'});
    const [saveJail, {loading: saving}] = useMutation(SAVE_JAIL, {
        refetchQueries: ['GetJails']
    });
    const [deleteJail, {loading: deleting}] = useMutation(DELETE_JAIL, {
        refetchQueries: ['GetJails']
    });

    const handleSave = async e => {
        e.preventDefault();
        if (!editingForm.name.trim()) {
            return;
        }

        try {
            const result = await saveJail({
                variables: {
                    name: editingForm.name.trim(),
                    enabled: editingForm.enabled,
                    maxRetry: Number.parseInt(editingForm.maxRetry, 10),
                    findTimeSeconds: Number.parseInt(editingForm.findTimeSeconds, 10),
                    banTimeSeconds: Number.parseInt(editingForm.banTimeSeconds, 10)
                }
            });
            if (result.data?.bruteForceLoginProtectionSaveJail) {
                setStatus('success');
                setEditingForm(null);
            } else {
                setStatus('error');
            }
        } catch (err) {
            console.error('Failed to save jail:', err);
            setStatus('error');
        }
    };

    const handleDelete = async name => {
        // eslint-disable-next-line no-alert
        if (!window.confirm(t('jails.confirmDelete', {name}))) {
            return;
        }

        try {
            const result = await deleteJail({variables: {name}});
            setStatus(result.data?.bruteForceLoginProtectionDeleteJail ? 'success' : 'error');
        } catch (err) {
            console.error('Failed to delete jail:', err);
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

    const jails = data?.bruteForceLoginProtectionJails || [];

    return (
        <div className={styles.bflp_tabPanel}>
            <div className={styles.bflp_sectionHeader}>
                <h3>{t('jails.title')}</h3>
                {!editingForm && (
                    <Button
                        label={t('jails.addJail')}
                        variant="primary"
                        onClick={() => setEditingForm({...EMPTY_FORM})}
                    />
                )}
            </div>
            <Typography className={styles.bflp_description}>{t('jails.description')}</Typography>

            <StatusAlerts status={status}/>

            {editingForm && (
                <form className={styles.bflp_addJailForm} onSubmit={handleSave} aria-label={t('jails.formTitle')}>
                    <div className={styles.bflp_fieldRow}>
                        <div className={styles.bflp_fieldGroup}>
                            <label className={styles.bflp_label} htmlFor="bflp-jail-name">{t('jails.name')}</label>
                            <input
                                id="bflp-jail-name"
                                type="text"
                                className={styles.bflp_input}
                                value={editingForm.name}
                                disabled={!editingForm.isNew}
                                aria-describedby="bflp-jail-name-hint"
                                onChange={e => setEditingForm(prev => ({...prev, name: e.target.value}))}
                            />
                            <p id="bflp-jail-name-hint" className={styles.bflp_hint}>{t('jails.nameHint')}</p>
                        </div>
                        <div className={styles.bflp_fieldGroup}>
                            <span id="bflp-jail-enabled-label" className={styles.bflp_label}>{t('jails.enabled')}</span>
                            <label className={styles.bflp_toggle}>
                                <input
                                    type="checkbox"
                                    aria-labelledby="bflp-jail-enabled-label"
                                    checked={editingForm.enabled}
                                    onChange={e => setEditingForm(prev => ({...prev, enabled: e.target.checked}))}
                                />
                                <span className={styles.bflp_toggleSlider}/>
                            </label>
                        </div>
                    </div>
                    <div className={styles.bflp_fieldRow}>
                        <div className={styles.bflp_fieldGroup}>
                            <label className={styles.bflp_label} htmlFor="bflp-jail-maxretry">{t('jails.maxRetry')}</label>
                            <input
                                id="bflp-jail-maxretry"
                                type="number"
                                min="1"
                                className={styles.bflp_input}
                                value={editingForm.maxRetry}
                                onChange={e => setEditingForm(prev => ({...prev, maxRetry: e.target.value}))}
                            />
                        </div>
                        <div className={styles.bflp_fieldGroup}>
                            <label className={styles.bflp_label} htmlFor="bflp-jail-findtime">{t('jails.findTimeSeconds')}</label>
                            <input
                                id="bflp-jail-findtime"
                                type="number"
                                min="1"
                                className={styles.bflp_input}
                                value={editingForm.findTimeSeconds}
                                onChange={e => setEditingForm(prev => ({...prev, findTimeSeconds: e.target.value}))}
                            />
                        </div>
                        <div className={styles.bflp_fieldGroup}>
                            <label className={styles.bflp_label} htmlFor="bflp-jail-bantime">{t('jails.banTimeSeconds')}</label>
                            <input
                                id="bflp-jail-bantime"
                                type="number"
                                min="1"
                                className={styles.bflp_input}
                                value={editingForm.banTimeSeconds}
                                onChange={e => setEditingForm(prev => ({...prev, banTimeSeconds: e.target.value}))}
                            />
                        </div>
                    </div>
                    <div className={styles.bflp_inlineActions}>
                        <Button
                            type="submit"
                            label={saving ? t('label.saving') : t('label.save')}
                            variant="primary"
                            isDisabled={saving || !editingForm.name.trim()}
                        />
                        <Button
                            label={t('label.cancel')}
                            variant="default"
                            isDisabled={saving}
                            onClick={() => setEditingForm(null)}
                        />
                    </div>
                </form>
            )}

            {jails.length === 0 ? (
                <Typography className={styles.bflp_emptyState}>{t('jails.noJails')}</Typography>
            ) : (
                <table className={styles.bflp_table}>
                    <thead>
                        <tr>
                            <th scope="col">{t('jails.colName')}</th>
                            <th scope="col">{t('jails.colEnabled')}</th>
                            <th scope="col">{t('jails.colMaxRetry')}</th>
                            <th scope="col">{t('jails.colFindTime')}</th>
                            <th scope="col">{t('jails.colBanTime')}</th>
                            <th scope="col">{t('jails.colActions')}</th>
                        </tr>
                    </thead>
                    <tbody>
                        {jails.map(j => (
                            <tr key={j.name}>
                                <td className={styles.bflp_ipCell}>{j.name}</td>
                                <td>
                                    <span className={`${styles.bflp_badge} ${j.enabled ? styles['bflp_badge--enabled'] : styles['bflp_badge--disabled']}`}>
                                        {j.enabled ? 'on' : 'off'}
                                    </span>
                                </td>
                                <td>{j.maxRetry}</td>
                                <td>{j.findTimeSeconds}</td>
                                <td>{j.banTimeSeconds}</td>
                                <td>
                                    <button
                                        type="button"
                                        className={styles.bflp_rowEditBtn}
                                        onClick={() => setEditingForm({
                                            name: j.name,
                                            enabled: j.enabled,
                                            maxRetry: j.maxRetry,
                                            findTimeSeconds: j.findTimeSeconds,
                                            banTimeSeconds: j.banTimeSeconds,
                                            isNew: false
                                        })}
                                    >
                                        {t('label.edit')}
                                    </button>
                                    <button
                                        type="button"
                                        className={styles.bflp_unbanBtn}
                                        disabled={deleting}
                                        onClick={() => handleDelete(j.name)}
                                    >
                                        {t('label.delete')}
                                    </button>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            )}
        </div>
    );
};

export default JailsTab;
