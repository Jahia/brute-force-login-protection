import {gql} from '@apollo/client';

export const GET_GLOBAL_SETTINGS = gql`
    query GetGlobalSettings {
        bruteForceLoginProtection {
            globalSettings {
                activated
                whitelistIps
                ignorePatterns
                trustProxyHeader
                trustedProxyCidrs
                emailEnabled
                emailRecipient
                webhookUrl
                webhookSecretConfigured
                auditLogMaxEntries
                recidiveFactor
                maxBanTimeSeconds
                blocklistIps
                torBlocklistEnabled
                torBlocklistUrl
                torBlocklistRefreshSeconds
            }
        }
    }
`;

export const SAVE_GLOBAL_SETTINGS = gql`
    mutation SaveGlobalSettings(
        $activated: Boolean,
        $whitelistIps: String,
        $ignorePatterns: [String!],
        $trustProxyHeader: Boolean,
        $trustedProxyCidrs: [String!],
        $emailEnabled: Boolean,
        $emailRecipient: String,
        $webhookUrl: String,
        $webhookSecret: String,
        $auditLogMaxEntries: Int,
        $recidiveFactor: Float,
        $maxBanTimeSeconds: Int,
        $blocklistIps: String,
        $torBlocklistEnabled: Boolean,
        $torBlocklistUrl: String,
        $torBlocklistRefreshSeconds: Int
    ) {
        bruteForceLoginProtection {
            saveGlobalSettings(
                activated: $activated,
                whitelistIps: $whitelistIps,
                ignorePatterns: $ignorePatterns,
                trustProxyHeader: $trustProxyHeader,
                trustedProxyCidrs: $trustedProxyCidrs,
                emailEnabled: $emailEnabled,
                emailRecipient: $emailRecipient,
                webhookUrl: $webhookUrl,
                webhookSecret: $webhookSecret,
                auditLogMaxEntries: $auditLogMaxEntries,
                recidiveFactor: $recidiveFactor,
                maxBanTimeSeconds: $maxBanTimeSeconds,
                blocklistIps: $blocklistIps,
                torBlocklistEnabled: $torBlocklistEnabled,
                torBlocklistUrl: $torBlocklistUrl,
                torBlocklistRefreshSeconds: $torBlocklistRefreshSeconds
            )
        }
    }
`;

export const GET_JAILS = gql`
    query GetJails {
        bruteForceLoginProtection {
            jails {
                name
                enabled
                maxRetry
                findTimeSeconds
                banTimeSeconds
            }
        }
    }
`;

export const SAVE_JAIL = gql`
    mutation SaveJail($name: String!, $enabled: Boolean, $maxRetry: Int, $findTimeSeconds: Int, $banTimeSeconds: Int) {
        bruteForceLoginProtection {
            saveJail(
                name: $name,
                enabled: $enabled,
                maxRetry: $maxRetry,
                findTimeSeconds: $findTimeSeconds,
                banTimeSeconds: $banTimeSeconds
            )
        }
    }
`;

export const DELETE_JAIL = gql`
    mutation DeleteJail($name: String!) {
        bruteForceLoginProtection {
            deleteJail(name: $name)
        }
    }
`;

export const GET_BANNED_IPS = gql`
    query GetBannedIps {
        bruteForceLoginProtection {
            bannedIps {
                ip
                jail
                source
                bannedAt
                bannedUntil
                banCount
                reason
                remainingSeconds
            }
        }
    }
`;

export const GET_TRACKED_WINDOWS = gql`
    query GetTrackedWindows {
        bruteForceLoginProtection {
            trackedWindows {
                ip
                jail
                failuresInWindow
                oldestFailureAt
                lastFailureAt
            }
        }
    }
`;

export const UNBAN_IP = gql`
    mutation UnbanIp($ip: String!) {
        bruteForceLoginProtection {
            unbanIp(ip: $ip)
        }
    }
`;

export const BAN_IP = gql`
    mutation BanIp($ip: String!, $jail: String, $durationSeconds: Int, $reason: String) {
        bruteForceLoginProtection {
            banIp(ip: $ip, jail: $jail, durationSeconds: $durationSeconds, reason: $reason)
        }
    }
`;

export const FLUSH = gql`
    mutation Flush {
        bruteForceLoginProtection {
            flush
        }
    }
`;

export const GET_AUDIT_LOG = gql`
    query GetAuditLog($limit: Int) {
        bruteForceLoginProtection {
            auditLog(limit: $limit) {
                id
                timestamp
                event
                ip
                jail
                source
                details
            }
        }
    }
`;

export const CLEAR_AUDIT_LOG = gql`
    mutation ClearAuditLog {
        bruteForceLoginProtection {
            clearAuditLog
        }
    }
`;

export const GET_BAN_ACTIONS = gql`
    query GetBanActions {
        bruteForceLoginProtection {
            banActions {
                name
                className
                priority
            }
        }
    }
`;

export const TEST_EMAIL = gql`
    mutation TestEmailIntegration {
        bruteForceLoginProtection {
            testEmail {
                success
                message
            }
        }
    }
`;

export const TEST_WEBHOOK = gql`
    mutation TestWebhookIntegration {
        bruteForceLoginProtection {
            testWebhook {
                success
                message
            }
        }
    }
`;

export const GET_BLOCKLIST_STATUS = gql`
    query GetBlocklistStatus {
        bruteForceLoginProtection {
            blocklistStatus {
                staticEntryCount
                torEnabled
                torUrl
                torRefreshSeconds
                torEntryCount
                torLastFetchTime
                torLastAttemptTime
                torLastError
                torListAgeSeconds
            }
        }
    }
`;

export const REFRESH_TOR_BLOCKLIST = gql`
    mutation RefreshTorBlocklist {
        bruteForceLoginProtection {
            refreshTorBlocklist {
                success
                message
            }
        }
    }
`;

export const GET_CLUSTER_STATUS = gql`
    query GetClusterStatus {
        bruteForceLoginProtection {
            clusterStatus {
                hazelcastRunning
                nodeCount
            }
        }
    }
`;
