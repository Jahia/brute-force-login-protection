package org.jahia.community.bruteforceloginprotection;

@SuppressWarnings("java:S1075") // JCR paths use '/' by spec
public final class BruteForceLoginProtectionConstants {
    private BruteForceLoginProtectionConstants() {}

    // JCR paths
    public static final String NODE_SETTINGS_PATH = "/settings";
    public static final String NODE_NAME = "bruteforceloginprotection";
    public static final String NODE_PATH = NODE_SETTINGS_PATH + "/" + NODE_NAME;
    public static final String BANS_NODE_NAME = "bans";
    public static final String BANS_NODE_PATH = NODE_PATH + "/" + BANS_NODE_NAME;
    public static final String AUDIT_NODE_NAME = "auditLog";
    public static final String AUDIT_NODE_PATH = NODE_PATH + "/" + AUDIT_NODE_NAME;

    // JCR node types
    public static final String NT_SETTINGS = "jnt:bruteForceLoginProtection";
    public static final String NT_BAN = "jnt:bruteForceLoginProtectionBan";
    public static final String NT_AUDIT_ENTRY = "jnt:bruteForceLoginProtectionAuditEntry";
    public static final String NT_BANS_CONTAINER = "jnt:bruteForceLoginProtectionBans";
    public static final String NT_AUDIT_CONTAINER = "jnt:bruteForceLoginProtectionAuditLog";

    // Per-ban property names
    public static final String PROP_BAN_IP = "ip";
    public static final String PROP_BAN_JAIL = "jail";
    public static final String PROP_BAN_SOURCE = "source";
    public static final String PROP_BAN_AT = "banned_at";
    public static final String PROP_BAN_UNTIL = "banned_until";
    public static final String PROP_BAN_COUNT = "ban_count";
    public static final String PROP_BAN_REASON = "reason";

    // Per-audit property names
    public static final String PROP_AUDIT_TIMESTAMP = "timestamp";
    public static final String PROP_AUDIT_EVENT = "event";
    public static final String PROP_AUDIT_IP = "ip";
    public static final String PROP_AUDIT_JAIL = "jail";
    public static final String PROP_AUDIT_SOURCE = "source";
    public static final String PROP_AUDIT_DETAILS = "details";

    // Hazelcast map names
    public static final String MAP_WINDOWS = "bflp:windows";
    public static final String MAP_BANS = "bflp:bans";
    public static final String MAP_NOTIFICATION_MARKERS = "bflp:notifMarkers";

    // Default jails (bootstrap on first activation)
    public static final String DEFAULT_JAIL_LOGIN = "login";

    // Defaults
    public static final int DEFAULT_MAX_RETRY = 6;
    public static final long DEFAULT_FIND_TIME_SEC = 600;
    public static final long DEFAULT_BAN_TIME_SEC = 3600;
    public static final long DEFAULT_MAX_BAN_TIME_SEC = 86400L * 7;
    public static final double DEFAULT_RECIDIVE_FACTOR = 2.0;
    public static final int DEFAULT_AUDIT_LOG_MAX = 1000;
    public static final int NOTIFICATION_THROTTLE_SECONDS = 3600;
    public static final String DEFAULT_WHITELIST = "127.0.0.1/32,::1/128";
}
