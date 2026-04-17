import {gql} from '@apollo/client';

export const GET_SETTINGS = gql`
    query {
        bruteForceLoginProtectionSettings {
            activated
            nbFailedLoginMax
            whitelistIps
        }
    }
`;

export const SAVE_SETTINGS = gql`
    mutation SaveSettings($activated: Boolean!, $nbFailedLoginMax: Int!, $whitelistIps: String!) {
        bruteForceLoginProtectionSaveSettings(activated: $activated, nbFailedLoginMax: $nbFailedLoginMax, whitelistIps: $whitelistIps)
    }
`;

export const FLUSH_CACHE = gql`
    mutation {
        bruteForceLoginProtectionFlushCache
    }
`;
