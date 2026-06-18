import React, {useCallback, useEffect, useRef} from 'react';
import {useTranslation} from 'react-i18next';
import styles from './BruteForceLoginProtection.scss';

/**
 * Accessible confirm dialog (WCAG 2.2 AAA).
 *
 * Satisfies:
 *   F-19 / F-30 — replaces window.confirm() with role="dialog" + aria-modal
 *   2.1.2       — focus trap: Tab/Shift+Tab cycle only between the two buttons
 *   2.1.1       — Escape cancels
 *   2.4.3       — focus moves into dialog on open, restores to trigger on close
 *   1.3.1       — semantic landmark + heading
 */
export const ConfirmDialog = ({isOpen, message, onConfirm, onCancel}) => {
    const {t} = useTranslation('brute-force-login-protection');
    const cancelRef = useRef(null);
    const confirmRef = useRef(null);
    const previousFocusRef = useRef(null);

    // Capture the previously-focused element when opening
    useEffect(() => {
        if (isOpen) {
            previousFocusRef.current = document.activeElement;
            // Defer so the dialog is rendered before we focus
            requestAnimationFrame(() => {
                cancelRef.current?.focus();
            });
        } else if (previousFocusRef.current) {
            previousFocusRef.current.focus();
            previousFocusRef.current = null;
        }
    }, [isOpen]);

    // Focus trap: keep Tab/Shift-Tab inside the dialog
    const handleKeyDown = useCallback(e => {
        if (e.key === 'Escape') {
            e.preventDefault();
            onCancel();
            return;
        }

        if (e.key !== 'Tab') {
            return;
        }

        const focusable = [cancelRef.current, confirmRef.current].filter(Boolean);
        if (focusable.length === 0) {
            return;
        }

        const first = focusable[0];
        const last = focusable[focusable.length - 1];

        if (e.shiftKey) {
            if (document.activeElement === first) {
                e.preventDefault();
                last.focus();
            }
        } else if (document.activeElement === last) {
            e.preventDefault();
            first.focus();
        }
    }, [onCancel]);

    if (!isOpen) {
        return null;
    }

    return (
        /* Backdrop */
        <div
            className={styles.bflp_dialogBackdrop}
            onClick={onCancel}
        >
            {/* Dialog panel — stop click propagation to backdrop */}
            <div
                aria-labelledby="bflp-dialog-title"
                aria-modal="true"
                className={styles.bflp_dialog}
                role="dialog"
                onClick={e => e.stopPropagation()}
                onKeyDown={handleKeyDown}
            >
                <h2 className={styles.bflp_dialogTitle} id="bflp-dialog-title">
                    {t('dialog.confirmTitle')}
                </h2>
                <p className={styles.bflp_dialogMessage}>{message}</p>
                <div className={styles.bflp_dialogActions}>
                    <button
                        ref={cancelRef}
                        className={styles.bflp_dialogCancelBtn}
                        type="button"
                        onClick={onCancel}
                    >
                        {t('dialog.cancel')}
                    </button>
                    <button
                        ref={confirmRef}
                        className={styles.bflp_dialogConfirmBtn}
                        type="button"
                        onClick={onConfirm}
                    >
                        {t('dialog.confirm')}
                    </button>
                </div>
            </div>
        </div>
    );
};

export default ConfirmDialog;
