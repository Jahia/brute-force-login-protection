import {useCallback, useEffect, useRef, useState} from 'react';

// Shared helper: status alert ('success' | 'error' | null) that auto-clears after `delay` ms.
export const useTransientStatus = (delay = 4000) => {
    const [status, setStatus] = useState(null);
    const timerRef = useRef(null);

    const setTransient = useCallback(value => {
        if (timerRef.current) {
            clearTimeout(timerRef.current);
        }

        setStatus(value);
        if (value) {
            timerRef.current = setTimeout(() => setStatus(null), delay);
        }
    }, [delay]);

    useEffect(() => () => {
        if (timerRef.current) {
            clearTimeout(timerRef.current);
        }
    }, []);

    return [status, setTransient];
};

// Render a pair of always-present live regions so AT can announce success/error.
// Returns JSX usable in any tab footer.
export const formatEpoch = ts => {
    if (!ts && ts !== 0) {
        return '';
    }

    try {
        return new Date(Number(ts)).toLocaleString();
    } catch (_) {
        return String(ts);
    }
};

export const formatDuration = seconds => {
    if (seconds === null || seconds === undefined) {
        return '';
    }

    const s = Math.max(0, Number(seconds));
    if (s < 60) {
        return `${s}s`;
    }

    const m = Math.floor(s / 60);
    const rem = s % 60;
    if (m < 60) {
        return rem === 0 ? `${m}m` : `${m}m ${rem}s`;
    }

    const h = Math.floor(m / 60);
    const remM = m % 60;
    return remM === 0 ? `${h}h` : `${h}h ${remM}m`;
};

// Basic CIDR sanity check (IPv4 or IPv6/n). Strict-ish, mirrors backend lenience.
const CIDR_REGEX = /^(?:(?:\d{1,3}\.){3}\d{1,3}\/\d{1,2}|[0-9a-fA-F:]+\/\d{1,3})$/;

export const validateWhitelist = value => {
    if (!value || !value.trim()) {
        return true;
    }

    return value
        .split(',')
        .map(part => part.trim())
        .filter(Boolean)
        .every(part => CIDR_REGEX.test(part));
};
