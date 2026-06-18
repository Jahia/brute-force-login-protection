import React, {useState} from 'react';
import {useMutation, useQuery} from '@apollo/client';
import {useTranslation} from 'react-i18next';
import {Button, Loader, Typography} from '@jahia/moonstone';
import styles from '../BruteForceLoginProtection.scss';
import {BAN_IP, GET_BANNED_IPS, UNBAN_IP} from '../BruteForceLoginProtection.gql';
import {StatusAlerts} from './StatusAlerts';
import {formatDuration, formatEpoch, useTransientStatus} from './useTransientStatus';

export const BansTab = () => {
    const {t} = useTranslation('brute-force-login-protection');
    const [status, setStatus] = useTransientStatus();
    const [unbanStatus, setUnbanStatus] = useTransientStatus();
    const [banForm, setBanForm] = useState({ip: '', jail: '', durationSeconds: '', reason: ''});
    const [banFormError, setBanFormError] = useState(null);

    const {data, loading} = useQuery(GET_BANNED_IPS, {fetchPolicy: 'network-only'});
    const [unbanIp, {loading: unbanning}] = useMutation(UNBAN_IP, {
        refetchQueries: ['GetBannedIps']
    });
    const [banIp, {loading: banning}] = useMutation(BAN_IP, {
        refetchQueries: ['GetBannedIps']
    });
    const [currentUnban, setCurrentUnban] = useState(null);

    const handleUnban = async ip => {
        setCurrentUnban(ip);
        try {
            const r = await unbanIp({variables: {ip}});
            setUnbanStatus(r.data?.bruteForceLoginProtectionUnbanIp ? 'success' : 'error');
        } catch (err) {
            console.error('Failed to unban IP:', err);
            setUnbanStatus('error');
        } finally {
            setCurrentUnban(null);
        }
    };

    const handleBan = async e => {
        e.preventDefault();
        setBanFormError(null);
        if (!banForm.ip.trim()) {
            setBanFormError(t('bans.ipRequired'));
            return;
        }

        try {
            const variables = {ip: banForm.ip.trim()};
            if (banForm.jail.trim()) {
                variables.jail = banForm.jail.trim();
            }

            if (banForm.durationSeconds) {
                variables.durationSeconds = Number.parseInt(banForm.durationSeconds, 10);
            }

            if (banForm.reason.trim()) {
                variables.reason = banForm.reason.trim();
            }

            const r = await banIp({variables});
            if (r.data?.bruteForceLoginProtectionBanIp) {
                setStatus('success');
                setBanForm({ip: '', jail: '', durationSeconds: '', reason: ''});
            } else {
                setStatus('error');
            }
        } catch (err) {
            console.error('Failed to ban IP:', err);
            setStatus('error');
        }
    };

    const bans = [...(data?.bruteForceLoginProtectionBannedIps || [])]
        .sort((a, b) => Number(b.bannedAt) - Number(a.bannedAt));

    return (
        <div className={styles.bflp_tabPanel}>
            <div className={styles.bflp_subSection}>
                <h3>{t('bans.banAnIp')}</h3>
                {/* F-09: fieldset/legend grouping; aria-label on form */}
                <form
                    aria-label={t('bans.banAnIp')}
                    className={styles.bflp_form}
                    onSubmit={handleBan}
                >
                    <fieldset className={styles.bflp_fieldset}>
                        <legend className={styles.bflp_fieldsetLegend}>{t('bans.banFormLegend')}</legend>
                        <div className={styles.bflp_fieldRow}>
                            <div className={styles.bflp_fieldGroup}>
                                {/* F-04: required + aria-required + visible indicator */}
                                <label className={styles.bflp_label} htmlFor="bflp-ban-ip">
                                    {t('bans.ip')}
                                    <span aria-hidden="true" className={styles.bflp_required}>*</span>
                                </label>
                                <input
                                    required
                                    aria-describedby={banFormError ? 'bflp-ban-ip-error' : undefined}
                                    aria-invalid={banFormError ? 'true' : undefined}
                                    aria-required="true"
                                    className={styles.bflp_input}
                                    id="bflp-ban-ip"
                                    type="text"
                                    value={banForm.ip}
                                    onChange={e => setBanForm(prev => ({...prev, ip: e.target.value}))}
                                />
                            </div>
                            <div className={styles.bflp_fieldGroup}>
                                <label className={styles.bflp_label} htmlFor="bflp-ban-jail">{t('bans.jail')}</label>
                                <input
                                    className={styles.bflp_input}
                                    id="bflp-ban-jail"
                                    type="text"
                                    value={banForm.jail}
                                    onChange={e => setBanForm(prev => ({...prev, jail: e.target.value}))}
                                />
                            </div>
                            <div className={styles.bflp_fieldGroup}>
                                <label className={styles.bflp_label} htmlFor="bflp-ban-duration">{t('bans.durationSeconds')}</label>
                                <input
                                    className={styles.bflp_input}
                                    id="bflp-ban-duration"
                                    min="1"
                                    type="number"
                                    value={banForm.durationSeconds}
                                    onChange={e => setBanForm(prev => ({...prev, durationSeconds: e.target.value}))}
                                />
                            </div>
                            <div className={styles.bflp_fieldGroup} style={{flex: 1, minWidth: 220}}>
                                <label className={styles.bflp_label} htmlFor="bflp-ban-reason">{t('bans.reason')}</label>
                                <input
                                    className={`${styles.bflp_input} ${styles['bflp_input--wide']}`}
                                    id="bflp-ban-reason"
                                    type="text"
                                    value={banForm.reason}
                                    onChange={e => setBanForm(prev => ({...prev, reason: e.target.value}))}
                                />
                            </div>
                        </div>
                    </fieldset>
                    {/* F-22/F-25/F-26: always-present error node (pre-rendered) */}
                    <p
                        aria-atomic="true"
                        aria-live="polite"
                        className={styles.bflp_fieldError}
                        id="bflp-ban-ip-error"
                    >
                        {banFormError || ''}
                    </p>
                    {/* F-22/F-25/F-26: pre-rendered live regions */}
                    <StatusAlerts status={status}/>
                    <div className={styles.bflp_inlineActions}>
                        <Button
                            isDisabled={banning}
                            label={banning ? t('bans.banning') : t('bans.banButton')}
                            type="submit"
                            variant="primary"
                        />
                    </div>
                </form>
            </div>

            <div className={styles.bflp_sectionHeader}>
                <h3>{t('bans.title')}</h3>
            </div>
            <Typography className={styles.bflp_description}>{t('bans.description')}</Typography>
            {/* F-22/F-25/F-26: pre-rendered live regions */}
            <StatusAlerts status={unbanStatus}/>

            {loading && (
                <div aria-busy="true" aria-live="polite" className={styles.bflp_loading}>
                    <Loader size="big"/>
                    <span className={styles.bflp_sr_only}>{t('label.loading')}</span>
                </div>
            )}

            {!loading && bans.length === 0 && (
                <Typography className={styles.bflp_emptyState}>{t('bans.noBans')}</Typography>
            )}

            {!loading && bans.length > 0 && (
                <table className={styles.bflp_table}>
                    {/* F-11: table caption */}
                    <caption className={styles.bflp_tableCaption}>{t('bans.tableCaption')}</caption>
                    <thead>
                        <tr>
                            {/* F-12: aria-sort on the bannedAt column (pre-sorted descending) */}
                            <th scope="col">{t('bans.colIp')}</th>
                            <th scope="col">{t('bans.colJail')}</th>
                            <th scope="col">{t('bans.colBanCount')}</th>
                            <th aria-sort="descending" scope="col">{t('bans.colBannedAt')}</th>
                            <th scope="col">{t('bans.colBannedUntil')}</th>
                            <th scope="col">{t('bans.colRemaining')}</th>
                            <th scope="col">{t('bans.colReason')}</th>
                            <th scope="col">{t('bans.colSource')}</th>
                            <th scope="col">{t('bans.colActions')}</th>
                        </tr>
                    </thead>
                    <tbody>
                        {bans.map(b => (
                            <tr key={`${b.ip}@${b.jail}`}>
                                <td className={styles.bflp_ipCell}>{b.ip}</td>
                                <td>{b.jail}</td>
                                <td>
                                    {b.banCount > 1 ? (
                                        <span className={`${styles.bflp_badge} ${styles['bflp_badge--recidive']}`}>
                                            {t('bans.recidive', {count: b.banCount})}
                                        </span>
                                    ) : b.banCount}
                                </td>
                                <td>{formatEpoch(b.bannedAt)}</td>
                                <td>{formatEpoch(b.bannedUntil)}</td>
                                <td>{formatDuration(b.remainingSeconds)}</td>
                                <td>{b.reason || ''}</td>
                                <td>{b.source || ''}</td>
                                {/* F-21/F-28: >=44x44 touch target */}
                                <td>
                                    <button
                                        aria-label={t('bans.unbanAria', {ip: b.ip})}
                                        className={styles.bflp_tableActionBtn}
                                        disabled={unbanning && currentUnban === b.ip}
                                        type="button"
                                        onClick={() => handleUnban(b.ip)}
                                    >
                                        {unbanning && currentUnban === b.ip ? t('bans.unbanning') : t('bans.unban')}
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

export default BansTab;
