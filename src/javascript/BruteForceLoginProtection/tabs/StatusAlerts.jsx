import React from 'react';
import {useTranslation} from 'react-i18next';
import styles from '../BruteForceLoginProtection.scss';

export const StatusAlerts = ({status, successMessage, errorMessage}) => {
    const {t} = useTranslation('brute-force-login-protection');
    const successText = successMessage || t('label.saveSuccess');
    const errorText = errorMessage || t('label.saveError');

    return (
        <>
            <div role="alert" aria-live="assertive" aria-atomic="true">
                {status === 'error' && (
                    <div className={`${styles.bflp_alert} ${styles['bflp_alert--error']}`}>
                        {errorText}
                    </div>
                )}
            </div>
            <div role="status" aria-live="polite" aria-atomic="true">
                {status === 'success' && (
                    <div className={`${styles.bflp_alert} ${styles['bflp_alert--success']}`}>
                        {successText}
                    </div>
                )}
            </div>
        </>
    );
};

export default StatusAlerts;
