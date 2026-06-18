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

    // Capture the previously-focused element on open, move focus into the
    // dialog, and reliably restore focus to the trigger when the dialog closes
    // or unmounts (effect cleanup covers both isOpen=false and unmount).
    useEffect(() => {
        if (!isOpen) {
            return undefined;
        }

        const previouslyFocused = document.activeElement;

        // Defer so the dialog is rendered before we focus
        const raf = requestAnimationFrame(() => {
            cancelRef.current?.focus();
        });

        return () => {
            cancelAnimationFrame(raf);
            if (previouslyFocused && typeof previouslyFocused.focus === 'function') {
                previouslyFocused.focus();
            }
        };
    }, [isOpen]);

    // Focus trap: keep Tab/Shift-Tab inside the dialog; Escape always cancels.
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

        // Fewer than two targets: keep focus pinned to the only one (or the
        // dialog) rather than letting Tab escape the modal.
        if (focusable.length < 2) {
            e.preventDefault();
            focusable[0]?.focus();
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
        /*
         * Presentational backdrop only — dismissal is via Escape or the explicit
         * Cancel/Confirm buttons. A bare click-to-dismiss div would have no role
         * or keyboard equivalent, so it is intentionally not interactive.
         */
        <div className={styles.bflp_dialogBackdrop}>
            <div
                aria-labelledby="bflp-dialog-title"
                aria-modal="true"
                className={styles.bflp_dialog}
                role="dialog"
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
