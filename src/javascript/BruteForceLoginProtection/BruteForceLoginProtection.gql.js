import {gql} from '@apollo/client';

export const GET_SETTINGS = gql`
    query {
        bruteForceLoginProtectionSettings {
            activated
            nbFailedLoginMax
            whitelistIps
            timeToIdle
        }
    }
`;

export const SAVE_SETTINGS = gql`
    mutation SaveSettings($activated: Boolean!, $nbFailedLoginMax: Int!, $whitelistIps: String!, $timeToIdle: Int) {
        bruteForceLoginProtectionSaveSettings(activated: $activated, nbFailedLoginMax: $nbFailedLoginMax, whitelistIps: $whitelistIps, timeToIdle: $timeToIdle)
    }
`;

export const FLUSH_CACHE = gql`
    mutation {
        bruteForceLoginProtectionFlushCache
    }
`;

export const GET_TRACKED_IPS = gql`
    query {
        bruteForceLoginProtectionTrackedIps {
            ip
            nbFailedLogins
            blocked
        }
    }
`;

export const UNBLOCK_IP = gql`
    mutation UnblockIp($ip: String!) {
        bruteForceLoginProtectionUnblockIp(ip: $ip)
    }
`;
