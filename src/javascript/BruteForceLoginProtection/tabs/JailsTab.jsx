import React, {useState} from 'react';
import {useMutation, useQuery} from '@apollo/client';
import {useTranslation} from 'react-i18next';
import {Button, Loader, Typography} from '@jahia/moonstone';
import styles from '../BruteForceLoginProtection.scss';
import {DELETE_JAIL, GET_JAILS, SAVE_JAIL} from '../BruteForceLoginProtection.gql';
import {ConfirmDialog} from '../ConfirmDialog';
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
    const [nameError, setNameError] = useState('');
    const [confirmDelete, setConfirmDelete] = useState(null); // Jail name to delete

    const {data, loading} = useQuery(GET_JAILS, {fetchPolicy: 'network-only'});
    const [saveJail, {loading: saving}] = useMutation(SAVE_JAIL, {
        refetchQueries: ['GetJails']
    });
    const [deleteJail, {loading: deleting}] = useMutation(DELETE_JAIL, {
        refetchQueries: ['GetJails']
    });

    const handleSave = async e => {
        e.preventDefault();
        setNameError('');
        // F-05: surface jail-name validation error
        if (!editingForm.name.trim()) {
            setNameError(t('jails.nameRequired'));
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

    // F-19/F-30: replaced window.confirm with ConfirmDialog
    const handleDeleteRequest = name => {
        setConfirmDelete(name);
    };

    const handleDeleteConfirm = async () => {
        const name = confirmDelete;
        setConfirmDelete(null);
        try {
            const result = await deleteJail({variables: {name}});
            setStatus(result.data?.bruteForceLoginProtectionDeleteJail ? 'success' : 'error');
        } catch (err) {
            console.error('Failed to delete jail:', err);
            setStatus('error');
        }
    };

    const handleDeleteCancel = () => {
        setConfirmDelete(null);
    };

    if (loading) {
        return (
            <div aria-busy="true" aria-live="polite" className={styles.bflp_loading}>
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

            {/* F-22/F-25/F-26: pre-rendered live regions */}
            <StatusAlerts status={status}/>

            {editingForm && (
                /* F-09: fieldset/legend grouping for the jail form */
                <form aria-label={t('jails.formTitle')} className={styles.bflp_addJailForm} onSubmit={handleSave}>
                    <fieldset className={styles.bflp_fieldset}>
                        <legend className={styles.bflp_fieldsetLegend}>{t('jails.identityLegend')}</legend>
                        <div className={styles.bflp_fieldRow}>
                            <div className={styles.bflp_fieldGroup}>
                                {/* F-04/F-05: required + aria-required + aria-invalid + aria-describedby */}
                                <label className={styles.bflp_label} htmlFor="bflp-jail-name">
                                    {t('jails.name')}
                                    <span aria-hidden="true" className={styles.bflp_required}>*</span>
                                </label>
                                <input
                                    required
                                    aria-describedby={nameError ? 'bflp-jail-name-hint bflp-jail-name-error' : 'bflp-jail-name-hint'}
                                    aria-invalid={nameError ? 'true' : undefined}
                                    aria-required="true"
                                    className={styles.bflp_input}
                                    disabled={!editingForm.isNew}
                                    id="bflp-jail-name"
                                    type="text"
                                    value={editingForm.name}
                                    onChange={e => {
                                        setNameError('');
                                        setEditingForm(prev => ({...prev, name: e.target.value}));
                                    }}
                                />
                                <p className={styles.bflp_hint} id="bflp-jail-name-hint">{t('jails.nameHint')}</p>
                                {/* F-05: always-present error node */}
                                <p
                                    aria-atomic="true"
                                    aria-live="polite"
                                    className={styles.bflp_fieldError}
                                    id="bflp-jail-name-error"
                                >
                                    {nameError || ''}
                                </p>
                            </div>
                            <div className={styles.bflp_fieldGroup}>
                                <span className={styles.bflp_label} id="bflp-jail-enabled-label">{t('jails.enabled')}</span>
                                <label className={styles.bflp_toggle}>
                                    <input
                                        aria-labelledby="bflp-jail-enabled-label"
                                        checked={editingForm.enabled}
                                        type="checkbox"
                                        onChange={e => setEditingForm(prev => ({...prev, enabled: e.target.checked}))}
                                    />
                                    <span className={styles.bflp_toggleSlider}/>
                                </label>
                            </div>
                        </div>
                    </fieldset>

                    <fieldset className={styles.bflp_fieldset}>
                        <legend className={styles.bflp_fieldsetLegend}>{t('jails.thresholdsLegend')}</legend>
                        <div className={styles.bflp_fieldRow}>
                            <div className={styles.bflp_fieldGroup}>
                                <label className={styles.bflp_label} htmlFor="bflp-jail-maxretry">{t('jails.maxRetry')}</label>
                                <input
                                    className={styles.bflp_input}
                                    id="bflp-jail-maxretry"
                                    min="1"
                                    type="number"
                                    value={editingForm.maxRetry}
                                    onChange={e => setEditingForm(prev => ({...prev, maxRetry: e.target.value}))}
                                />
                            </div>
                            <div className={styles.bflp_fieldGroup}>
                                <label className={styles.bflp_label} htmlFor="bflp-jail-findtime">{t('jails.findTimeSeconds')}</label>
                                <input
                                    className={styles.bflp_input}
                                    id="bflp-jail-findtime"
                                    min="1"
                                    type="number"
                                    value={editingForm.findTimeSeconds}
                                    onChange={e => setEditingForm(prev => ({...prev, findTimeSeconds: e.target.value}))}
                                />
                            </div>
                            <div className={styles.bflp_fieldGroup}>
                                <label className={styles.bflp_label} htmlFor="bflp-jail-bantime">{t('jails.banTimeSeconds')}</label>
                                <input
                                    className={styles.bflp_input}
                                    id="bflp-jail-bantime"
                                    min="1"
                                    type="number"
                                    value={editingForm.banTimeSeconds}
                                    onChange={e => setEditingForm(prev => ({...prev, banTimeSeconds: e.target.value}))}
                                />
                            </div>
                        </div>
                    </fieldset>

                    <div className={styles.bflp_inlineActions}>
                        <Button
                            isDisabled={saving || !editingForm.name.trim()}
                            label={saving ? t('label.saving') : t('label.save')}
                            type="submit"
                            variant="primary"
                        />
                        <Button
                            isDisabled={saving}
                            label={t('label.cancel')}
                            variant="default"
                            onClick={() => {
                                setNameError('');
                                setEditingForm(null);
                            }}
                        />
                    </div>
                </form>
            )}

            {jails.length === 0 ? (
                <Typography className={styles.bflp_emptyState}>{t('jails.noJails')}</Typography>
            ) : (
                <table className={styles.bflp_table}>
                    {/* F-11: table caption */}
                    <caption className={styles.bflp_tableCaption}>{t('jails.tableCaption')}</caption>
                    <thead>
                        <tr>
                            {/* F-12: aria-sort on the pre-sorted Name column */}
                            <th aria-sort="ascending" scope="col">{t('jails.colName')}</th>
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
                                    {/* F-13: i18n for on/off */}
                                    <span className={`${styles.bflp_badge} ${j.enabled ? styles['bflp_badge--enabled'] : styles['bflp_badge--disabled']}`}>
                                        {j.enabled ? t('label.on') : t('label.off')}
                                    </span>
                                </td>
                                <td>{j.maxRetry}</td>
                                <td>{j.findTimeSeconds}</td>
                                <td>{j.banTimeSeconds}</td>
                                {/* F-21/F-28: table action buttons >=44x44 via bflp_tableActionBtn */}
                                <td>
                                    <button
                                        className={styles.bflp_tableActionBtn}
                                        type="button"
                                        onClick={() => setEditingForm({
                                            banTimeSeconds: j.banTimeSeconds,
                                            enabled: j.enabled,
                                            findTimeSeconds: j.findTimeSeconds,
                                            isNew: false,
                                            maxRetry: j.maxRetry,
                                            name: j.name
                                        })}
                                    >
                                        {t('label.edit')}
                                    </button>
                                    <button
                                        className={styles.bflp_tableActionBtn}
                                        disabled={deleting}
                                        type="button"
                                        onClick={() => handleDeleteRequest(j.name)}
                                    >
                                        {t('label.delete')}
                                    </button>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            )}

            {/* F-19/F-30: accessible confirm dialog for delete */}
            <ConfirmDialog
                isOpen={Boolean(confirmDelete)}
                message={t('jails.confirmDelete', {name: confirmDelete})}
                onCancel={handleDeleteCancel}
                onConfirm={handleDeleteConfirm}
            />
        </div>
    );
};

export default JailsTab;
