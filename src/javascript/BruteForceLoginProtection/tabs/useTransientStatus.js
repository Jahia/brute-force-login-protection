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

// CIDR sanity check (IPv4 or IPv6/n).
// IPv4: each octet 0-255 and prefix length 0-32.
// IPv6: hex/':' groups with prefix length 0-128.
const OCTET = '(?:25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)'; // 0-255
const IPV4_PREFIX = '(?:3[0-2]|[12]?\\d)'; // 0-32
const IPV6_PREFIX = '(?:12[0-8]|1[01]\\d|\\d?\\d)'; // 0-128
const IPV4_CIDR = `(?:${OCTET}\\.){3}${OCTET}\\/${IPV4_PREFIX}`;
const IPV6_CIDR = `[0-9a-fA-F:]+\\/${IPV6_PREFIX}`;
const CIDR_REGEX = new RegExp(`^(?:${IPV4_CIDR}|${IPV6_CIDR})$`);

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
