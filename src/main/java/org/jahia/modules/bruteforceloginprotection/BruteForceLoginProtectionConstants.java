package org.jahia.modules.bruteforceloginprotection;

import org.apache.jackrabbit.commons.webdav.JcrRemotingConstants;
import org.apache.jackrabbit.core.fs.FileSystem;

public final class BruteForceLoginProtectionConstants {

    public static final String PROPERTY_ACTIVATED = "activated";
    public static final String PROPERTY_NB_FAILED_LOGIN_MAX = "nb_failed_login_max";
    public static final String PROPERTY_WHITELIST_IPS = "whitelist_ips";
    public static final String PROPERTY_TIME_TO_IDLE = "time_to_idle";
    public static final String PROPERTY_TRUST_PROXY_HEADER = "trust_x_forwarded_for";
    public static final int DEFAULT_TIME_TO_IDLE = 3600;
    public static final int MAX_CACHE_ENTRIES = 100_000;
    public static final int NOTIFICATION_THROTTLE_SECONDS = 3600;
    public static final String NODE_NAME = "bruteforceloginprotection";
    public static final String NODE_SETTINGS_PATH = JcrRemotingConstants.ROOT_ITEM_PATH + "settings";
    public static final String NODE_PATH = NODE_SETTINGS_PATH + FileSystem.SEPARATOR + NODE_NAME;

    private BruteForceLoginProtectionConstants() {
    }
}
