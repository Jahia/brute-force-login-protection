import {gql} from '@apollo/client';

export const GET_GLOBAL_SETTINGS = gql`
    query GetGlobalSettings {
        bruteForceLoginProtectionGlobalSettings {
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
        $maxBanTimeSeconds: Int
    ) {
        bruteForceLoginProtectionSaveGlobalSettings(
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
            maxBanTimeSeconds: $maxBanTimeSeconds
        )
    }
`;

export const GET_JAILS = gql`
    query GetJails {
        bruteForceLoginProtectionJails {
            name
            enabled
            maxRetry
            findTimeSeconds
            banTimeSeconds
        }
    }
`;

export const SAVE_JAIL = gql`
    mutation SaveJail($name: String!, $enabled: Boolean, $maxRetry: Int, $findTimeSeconds: Int, $banTimeSeconds: Int) {
        bruteForceLoginProtectionSaveJail(
            name: $name,
            enabled: $enabled,
            maxRetry: $maxRetry,
            findTimeSeconds: $findTimeSeconds,
            banTimeSeconds: $banTimeSeconds
        )
    }
`;

export const DELETE_JAIL = gql`
    mutation DeleteJail($name: String!) {
        bruteForceLoginProtectionDeleteJail(name: $name)
    }
`;

export const GET_BANNED_IPS = gql`
    query GetBannedIps {
        bruteForceLoginProtectionBannedIps {
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
`;

export const GET_TRACKED_WINDOWS = gql`
    query GetTrackedWindows {
        bruteForceLoginProtectionTrackedWindows {
            ip
            jail
            failuresInWindow
            oldestFailureAt
            lastFailureAt
        }
    }
`;

export const UNBAN_IP = gql`
    mutation UnbanIp($ip: String!) {
        bruteForceLoginProtectionUnbanIp(ip: $ip)
    }
`;

export const BAN_IP = gql`
    mutation BanIp($ip: String!, $jail: String, $durationSeconds: Int, $reason: String) {
        bruteForceLoginProtectionBanIp(ip: $ip, jail: $jail, durationSeconds: $durationSeconds, reason: $reason)
    }
`;

export const FLUSH = gql`
    mutation Flush {
        bruteForceLoginProtectionFlush
    }
`;

export const GET_AUDIT_LOG = gql`
    query GetAuditLog($limit: Int) {
        bruteForceLoginProtectionAuditLog(limit: $limit) {
            id
            timestamp
            event
            ip
            jail
            source
            details
        }
    }
`;

export const CLEAR_AUDIT_LOG = gql`
    mutation ClearAuditLog {
        bruteForceLoginProtectionClearAuditLog
    }
`;

export const GET_BAN_ACTIONS = gql`
    query GetBanActions {
        bruteForceLoginProtectionBanActions {
            name
            className
            priority
        }
    }
`;

export const TEST_EMAIL = gql`
    mutation TestEmailIntegration {
        bruteForceLoginProtectionTestEmail {
            success
            message
        }
    }
`;

export const TEST_WEBHOOK = gql`
    mutation TestWebhookIntegration {
        bruteForceLoginProtectionTestWebhook {
            success
            message
        }
    }
`;

export const GET_CLUSTER_STATUS = gql`
    query GetClusterStatus {
        bruteForceLoginProtectionClusterStatus {
            hazelcastRunning
            nodeCount
        }
    }
`;
