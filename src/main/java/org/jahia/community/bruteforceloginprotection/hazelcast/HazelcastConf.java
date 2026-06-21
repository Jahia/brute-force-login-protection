package org.jahia.community.bruteforceloginprotection.hazelcast;

import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;

@Component(immediate = true, service = HazelcastConf.class)
public class HazelcastConf {

    public static final String CONFIG_FILE_NAME = "hazelcast-bflp.xml";
    public static final String GROUP_NAME = "brute-force-login-protection-bflp";
    public static final String INSTANCE_NAME_PREFIX = "bflp-";
    public static final String BIND_PORT_PROPERTY = "cluster.hazelcastbflp.bindPort";
    public static final String BASE_BIND_PORT_PROPERTY = "cluster.hazelcast.bindPort";

    @Activate
    public void init() {
        // No-op; values are static constants.
    }
}
