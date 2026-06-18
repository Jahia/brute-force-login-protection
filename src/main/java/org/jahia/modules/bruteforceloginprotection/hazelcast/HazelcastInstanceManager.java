package org.jahia.modules.bruteforceloginprotection.hazelcast;

import com.hazelcast.config.Config;
import com.hazelcast.config.GlobalSerializerConfig;
import com.hazelcast.config.SSLConfig;
import com.hazelcast.config.TcpIpConfig;
import com.hazelcast.config.XmlConfigBuilder;
import com.hazelcast.core.Hazelcast;
import com.hazelcast.core.HazelcastInstance;
import org.apache.commons.lang.StringUtils;
import org.apache.karaf.cellar.core.ClusterManager;
import org.apache.karaf.cellar.core.discovery.DiscoveryService;
import org.apache.karaf.cellar.core.utils.CellarUtils;
import org.jahia.settings.SettingsBean;
import org.jahia.utils.ClassLoaderUtils;
import org.osgi.framework.BundleContext;
import org.osgi.framework.BundleListener;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.osgi.service.component.annotations.ReferencePolicyOption;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

@Component(immediate = true, service = HazelcastInstanceManager.class)
public class HazelcastInstanceManager implements Runnable {

    private static final Logger logger = LoggerFactory.getLogger(HazelcastInstanceManager.class);
    private static final String CLUSTER_PASSWORD_PROPERTY = "bflp.cluster.password";
    private static final String CLUSTER_SECRET_FILE = "bflp-cluster-secret.properties";
    private static final String CLUSTER_KEYSTORE_PROPERTY = "bflp.cluster.keystore";
    private static final String CLUSTER_KEYSTORE_PASSWORD_PROPERTY = "bflp.cluster.keystorePassword";
    private static final String CLUSTER_TRUSTSTORE_PROPERTY = "bflp.cluster.truststore";
    private static final String CLUSTER_TRUSTSTORE_PASSWORD_PROPERTY = "bflp.cluster.truststorePassword";

    // Mutated by dynamic OSGi @Reference bind/unbind from arbitrary threads while the discovery
    // scheduler iterates it — CopyOnWriteArrayList avoids ConcurrentModificationException.
    private final List<DiscoveryService> discoveryServices = new CopyOnWriteArrayList<>();
    private final BundleListener flushClassLoaderCacheBundleListener = event -> ClassLoaderUtil.flushCache();

    private ClassLoader classLoader;
    // Written in @Activate (SCR thread), read from the discovery scheduler thread and getters —
    // AtomicReference for safe cross-thread publication without S3077 volatile-object concern.
    private final AtomicReference<HazelcastInstance> hazelcastInstance = new AtomicReference<>();
    // Written from both @Activate and the discovery scheduler thread, read from both.
    // An AtomicReference holding an unmodifiable snapshot avoids the S3077 volatile-collection
    // issue and ensures safe cross-thread publication without mutation through the reference.
    private final AtomicReference<Set<String>> discoveredMembers =
            new AtomicReference<>(java.util.Collections.emptySet());
    // Created in @Activate and shut down in @Deactivate so that a deactivate/reactivate cycle
    // always starts with a fresh, running executor (avoids RejectedExecutionException).
    private ScheduledExecutorService scheduler;

    @Reference(service = DiscoveryService.class,
            policy = ReferencePolicy.DYNAMIC,
            cardinality = ReferenceCardinality.MULTIPLE,
            policyOption = ReferencePolicyOption.GREEDY,
            unbind = "removeDiscoveryService")
    public void addDiscoveryService(DiscoveryService discoveryService) {
        this.discoveryServices.add(discoveryService);
    }

    public void removeDiscoveryService(DiscoveryService discoveryService) {
        this.discoveryServices.remove(discoveryService);
    }

    @Reference(cardinality = ReferenceCardinality.OPTIONAL)
    public void setClusterManager(ClusterManager clusterManager) {
        // OSGi reference kept for declarative service wiring; no internal state needed.
    }

    public void unsetClusterManager() {
        // no-op
    }

    public HazelcastInstance getHazelcastInstance() {
        return hazelcastInstance.get();
    }

    public boolean isRunning() {
        HazelcastInstance hz = hazelcastInstance.get();
        return hz != null && hz.getLifecycleService().isRunning();
    }

    public int getClusterNodeCount() {
        if (!isRunning()) {
            return 0;
        }
        return hazelcastInstance.get().getCluster().getMembers().size();
    }

    @Activate
    protected void init(BundleContext bundleContext) {
        // Create a fresh executor on every activation so that a deactivate/reactivate cycle does
        // not reuse the previously shut-down instance (which would throw RejectedExecutionException).
        this.scheduler = Executors.newScheduledThreadPool(1);
        this.classLoader = new ClassLoaderUtils.CoreAndModulesClassLoader(ClassLoaderUtils.CoreAndModulesClassLoader.class.getClassLoader());
        ClassLoaderUtil.flushCache();

        try {
            Config hazelcastConfig = buildConfig(bundleContext);
            if (hazelcastConfig == null) {
                logger.warn("BFLP: Falling back to default single-node Hazelcast configuration");
                hazelcastConfig = new Config();
                hazelcastConfig.getGroupConfig().setName(HazelcastConf.GROUP_NAME);
                hazelcastConfig.setInstanceName(HazelcastConf.INSTANCE_NAME_PREFIX + "standalone");
                hazelcastConfig.getNetworkConfig().getJoin().getMulticastConfig().setEnabled(false);
                hazelcastConfig.getNetworkConfig().getJoin().getTcpIpConfig().setEnabled(false);
                hazelcastConfig.setClassLoader(classLoader);
            }

            TcpIpConfig tcpIpConfig = hazelcastConfig.getNetworkConfig().getJoin().getTcpIpConfig();
            if (tcpIpConfig.isEnabled() && !discoveryServices.isEmpty()) {
                discoveredMembers.set(java.util.Collections.unmodifiableSet(getCurrentMembers()));
                Set<String> members = discoveredMembers.get();
                if (!members.isEmpty()) {
                    tcpIpConfig.setMembers(new LinkedList<>(members));
                }
                logger.info("BFLP: initial members {}", members);
                hazelcastInstance.set(Hazelcast.getOrCreateHazelcastInstance(hazelcastConfig));
                scheduler.scheduleWithFixedDelay(this, 10, 10, TimeUnit.SECONDS);
            } else {
                hazelcastInstance.set(Hazelcast.getOrCreateHazelcastInstance(hazelcastConfig));
                logger.info("BFLP: Hazelcast started in single-node mode");
            }

            bundleContext.addBundleListener(flushClassLoaderCacheBundleListener);
        } catch (Exception e) {
            logger.error("BFLP: Unable to start Hazelcast instance", e);
        }
    }

    @Deactivate
    protected void destroy(BundleContext bundleContext) {
        logger.info("BFLP: shutting down");
        // Wait for the discovery task to finish so it cannot touch the Hazelcast instance or
        // bundle classloader after they are torn down below.
        if (scheduler != null) {
            scheduler.shutdownNow();
            try {
                if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                    logger.warn("BFLP: discovery scheduler did not terminate within 5s");
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            scheduler = null;
        }
        try {
            bundleContext.removeBundleListener(flushClassLoaderCacheBundleListener);
        } catch (Exception e) {
            logger.debug("BFLP: error removing bundle listener", e);
        }
        HazelcastInstance hz = hazelcastInstance.get();
        if (hz != null) {
            try {
                hz.shutdown();
            } catch (Exception e) {
                logger.debug("BFLP: error shutting down hazelcast", e);
            }
            hazelcastInstance.set(null);
        }
        ClassLoaderUtil.flushCache();
        this.classLoader = null;
    }

    private Config buildConfig(BundleContext bundleContext) {
        Path path;
        try {
            path = Paths.get(SettingsBean.getInstance().getJahiaVarDiskPath(), "karaf", "etc", HazelcastConf.CONFIG_FILE_NAME);
        } catch (Exception e) {
            logger.warn("BFLP: cannot resolve Jahia karaf etc dir", e);
            return null;
        }
        if (!path.toFile().exists()) {
            try (InputStream is = bundleContext.getBundle().getResource("META-INF/configurations/" + HazelcastConf.CONFIG_FILE_NAME).openStream()) {
                Files.createDirectories(path.getParent());
                Files.copy(is, path, StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException e) {
                logger.error("BFLP: cannot copy configuration file", e);
                return null;
            }
        }

        // Ensure a per-install cluster password exists in a sibling secret file and is set
        // as a system property so the Hazelcast XML placeholder resolves.
        ensureClusterPassword(path.getParent());

        String basePortStr = System.getProperty(HazelcastConf.BASE_BIND_PORT_PROPERTY);
        if (StringUtils.isNotBlank(basePortStr)) {
            try {
                System.setProperty(HazelcastConf.BIND_PORT_PROPERTY, Integer.toString(Integer.parseInt(basePortStr) + 2));
            } catch (NumberFormatException e) {
                logger.warn("BFLP: invalid {}={}, falling back to default", HazelcastConf.BASE_BIND_PORT_PROPERTY, basePortStr);
                System.setProperty(HazelcastConf.BIND_PORT_PROPERTY, "5703");
            }
        } else if (System.getProperty(HazelcastConf.BIND_PORT_PROPERTY) == null) {
            System.setProperty(HazelcastConf.BIND_PORT_PROPERTY, "5703");
        }
        if (System.getProperty("cluster.tcp.bindAddress") == null) {
            System.setProperty("cluster.tcp.bindAddress", "127.0.0.1");
        }

        Config config;
        try {
            config = new XmlConfigBuilder(path.toFile().getPath()).build();
        } catch (Exception e) {
            logger.error("BFLP: error parsing Hazelcast XML config", e);
            return null;
        }

        config.getSerializationConfig().setGlobalSerializerConfig(
                new GlobalSerializerConfig()
                        .setImplementation(new ClassLoaderAwareSerializer())
                        .setOverrideJavaSerialization(true));
        config.setClassLoader(classLoader);

        configureTlsIfRequested(config);

        String serverId = System.getProperty("cluster.node.serverId", "single");
        config.setInstanceName(HazelcastConf.INSTANCE_NAME_PREFIX + serverId);
        return config;
    }

    /**
     * Make sure a per-install Hazelcast cluster password is available. If the operator has
     * already exported one via {@code -Dbflp.cluster.password=...}, that value wins. Otherwise
     * we read (or generate) a sibling {@code bflp-cluster-secret.properties} file next to the
     * Hazelcast configuration and set the JVM system property from it so the
     * {@code ${bflp.cluster.password}} placeholder in the XML resolves.
     */
    private void ensureClusterPassword(Path etcDir) {
        if (StringUtils.isNotBlank(System.getProperty(CLUSTER_PASSWORD_PROPERTY))) {
            return;
        }
        Path secretFile = etcDir.resolve(CLUSTER_SECRET_FILE);
        Properties props = loadSecretProps(secretFile);
        String password = props.getProperty(CLUSTER_PASSWORD_PROPERTY);
        if (StringUtils.isBlank(password)) {
            password = generateAndPersistSecret(secretFile, props);
        }
        System.setProperty(CLUSTER_PASSWORD_PROPERTY, password);
    }

    private static Properties loadSecretProps(Path secretFile) {
        Properties props = new Properties();
        if (Files.exists(secretFile)) {
            try (InputStream is = Files.newInputStream(secretFile)) {
                props.load(is);
            } catch (IOException e) {
                logger.warn("BFLP: cannot read cluster secret file {}: {}", secretFile, e.getMessage());
            }
        }
        return props;
    }

    private static String generateAndPersistSecret(Path secretFile, Properties props) {
        byte[] random = new byte[32];
        new SecureRandom().nextBytes(random);
        String password = Base64.getEncoder().encodeToString(random);
        props.setProperty(CLUSTER_PASSWORD_PROPERTY, password);
        try {
            if (!Files.exists(secretFile)) {
                Files.createFile(secretFile);
            }
            try (java.io.OutputStream os = Files.newOutputStream(secretFile)) {
                props.store(os, "BFLP cluster shared secret (auto-generated; do not edit)");
            }
            restrictSecretFilePermissions(secretFile);
            logger.info("BFLP: generated per-install Hazelcast cluster secret at {}", secretFile);
        } catch (IOException e) {
            logger.warn("BFLP: cannot persist cluster secret file {}: {}", secretFile, e.getMessage());
        }
        return password;
    }

    private static void restrictSecretFilePermissions(Path secretFile) {
        try {
            Files.setPosixFilePermissions(secretFile,
                    PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException permEx) {
            // Non-POSIX FS (typically Windows) — fall back to ACL granting only the owner.
            if (!tryRestrictWithAcl(secretFile)) {
                logger.warn("BFLP: could not lock down cluster secret file {} via POSIX or ACL; please restrict it manually",
                        secretFile);
            }
        } catch (IOException permEx) {
            logger.warn("BFLP: cannot apply POSIX permissions on {}: {}", secretFile, permEx.getMessage());
        }
    }

    /**
     * Best-effort Windows/ACL fallback when {@link Files#setPosixFilePermissions} is not
     * supported. Grants the file owner full access via an explicit ACL and removes all other
     * entries. Returns {@code false} on any failure so the caller can log a WARN.
     */
    private static boolean tryRestrictWithAcl(Path file) {
        try {
            AclFileAttributeView view = Files.getFileAttributeView(file, AclFileAttributeView.class);
            if (view == null) {
                return false;
            }
            UserPrincipal owner = Files.getOwner(file);
            AclEntry entry = AclEntry.newBuilder()
                    .setType(java.nio.file.attribute.AclEntryType.ALLOW)
                    .setPrincipal(owner)
                    .setPermissions(
                            AclEntryPermission.READ_DATA,
                            AclEntryPermission.WRITE_DATA,
                            AclEntryPermission.APPEND_DATA,
                            AclEntryPermission.READ_ATTRIBUTES,
                            AclEntryPermission.WRITE_ATTRIBUTES,
                            AclEntryPermission.READ_ACL,
                            AclEntryPermission.WRITE_ACL,
                            AclEntryPermission.DELETE,
                            AclEntryPermission.SYNCHRONIZE)
                    .build();
            view.setAcl(java.util.Collections.singletonList(entry));
            return true;
        } catch (Exception e) {
            logger.debug("BFLP: ACL fallback failed for {}: {}", file, e.getMessage());
            return false;
        }
    }

    /**
     * Programmatically enable Hazelcast TLS when a keystore is configured via
     * {@code -Dbflp.cluster.keystore=...}. If no keystore is configured, leave cluster traffic
     * as-is (the XML defaults to {@code ssl enabled="false"}).
     */
    private void configureTlsIfRequested(Config config) {
        String keystore = System.getProperty(CLUSTER_KEYSTORE_PROPERTY);
        if (StringUtils.isBlank(keystore)) {
            return;
        }
        SSLConfig sslConfig = new SSLConfig();
        sslConfig.setEnabled(true);
        sslConfig.setFactoryClassName("com.hazelcast.nio.ssl.BasicSSLContextFactory");
        sslConfig.setProperty("keyStore", keystore);
        String keyStorePassword = System.getProperty(CLUSTER_KEYSTORE_PASSWORD_PROPERTY);
        if (keyStorePassword != null) {
            sslConfig.setProperty("keyStorePassword", keyStorePassword);
        }
        String truststore = System.getProperty(CLUSTER_TRUSTSTORE_PROPERTY);
        if (StringUtils.isNotBlank(truststore)) {
            sslConfig.setProperty("trustStore", truststore);
        }
        String trustStorePassword = System.getProperty(CLUSTER_TRUSTSTORE_PASSWORD_PROPERTY);
        if (trustStorePassword != null) {
            sslConfig.setProperty("trustStorePassword", trustStorePassword);
        }
        sslConfig.setProperty("protocol", "TLS");
        config.getNetworkConfig().setSSLConfig(sslConfig);
        logger.info("BFLP: Hazelcast TLS enabled (keystore={})", keystore);
    }

    @Override
    public void run() {
        // Guard against firing after a failed activation or during/after deactivation.
        HazelcastInstance hz = hazelcastInstance.get();
        if (hz == null || !isRunning()) {
            return;
        }
        Set<String> currentMembers = getCurrentMembers();
        if (!CellarUtils.collectionEquals(discoveredMembers.get(), currentMembers)) {
            logger.info("BFLP: members changed from {} to {}", discoveredMembers.get(), currentMembers);
            discoveredMembers.set(java.util.Collections.unmodifiableSet(currentMembers));
            hz.getConfig().getNetworkConfig().getJoin().getTcpIpConfig().setMembers(new LinkedList<>(currentMembers));
        }
    }

    private Set<String> getCurrentMembers() {
        Set<String> discoveredMemberSet = new HashSet<>();
        if (!discoveryServices.isEmpty()) {
            for (DiscoveryService service : discoveryServices) {
                try {
                    service.refresh();
                    discoveredMemberSet.addAll(incrementPortNumber(service.discoverMembers()));
                } catch (Exception e) {
                    logger.debug("BFLP: discovery service failure", e);
                }
            }
        }
        return discoveredMemberSet;
    }

    private static Set<String> incrementPortNumber(Set<String> members) {
        Set<String> newMembers = new HashSet<>();
        for (String member : members) {
            String[] parts = StringUtils.split(member, ':');
            if (parts.length == 2) {
                try {
                    newMembers.add(parts[0] + ":" + (Integer.parseInt(parts[1]) + 2));
                } catch (NumberFormatException ignored) {
                    // skip
                }
            }
        }
        return newMembers;
    }
}
