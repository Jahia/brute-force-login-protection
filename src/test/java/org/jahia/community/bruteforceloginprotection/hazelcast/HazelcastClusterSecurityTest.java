package org.jahia.community.bruteforceloginprotection.hazelcast;

import com.hazelcast.config.Config;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributeView;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * F9 — cluster security hardening: per-install shared-secret generation/persistence
 * ({@code ensureClusterPassword}) and mTLS keystore/truststore wiring
 * ({@code configureTlsIfRequested}). Both are private instance methods, invoked here via
 * reflection (same pattern used throughout this suite, e.g.
 * {@code HazelcastInstanceManagerShutdownTest}).
 */
public class HazelcastClusterSecurityTest {

    private static final String PASSWORD_PROPERTY = "bflp.cluster.password";
    private static final String KEYSTORE_PROPERTY = "bflp.cluster.keystore";
    private static final String KEYSTORE_PASSWORD_PROPERTY = "bflp.cluster.keystorePassword";
    private static final String TRUSTSTORE_PROPERTY = "bflp.cluster.truststore";
    private static final String TRUSTSTORE_PASSWORD_PROPERTY = "bflp.cluster.truststorePassword";

    private static final Set<String> MANAGED_PROPERTIES = Set.of(
            PASSWORD_PROPERTY, KEYSTORE_PROPERTY, KEYSTORE_PASSWORD_PROPERTY,
            TRUSTSTORE_PROPERTY, TRUSTSTORE_PASSWORD_PROPERTY);

    @Before
    public void clearManagedProperties() {
        MANAGED_PROPERTIES.forEach(System::clearProperty);
    }

    @After
    public void restoreManagedProperties() {
        // Reset again after the test so no system-property leakage affects any other test class
        // sharing this JVM (surefire may run tests in the same fork).
        MANAGED_PROPERTIES.forEach(System::clearProperty);
    }

    private static void invokeEnsureClusterPassword(HazelcastInstanceManager manager, Path etcDir) throws Exception {
        Method m = HazelcastInstanceManager.class.getDeclaredMethod("ensureClusterPassword", Path.class);
        m.setAccessible(true);
        m.invoke(manager, etcDir);
    }

    private static void invokeConfigureTls(HazelcastInstanceManager manager, Config config) throws Exception {
        Method m = HazelcastInstanceManager.class.getDeclaredMethod("configureTlsIfRequested", Config.class);
        m.setAccessible(true);
        m.invoke(manager, config);
    }

    // -------------------------------------------------------------------------------------------
    // Cluster shared-secret generation / persistence
    // -------------------------------------------------------------------------------------------

    @Test
    public void firstRunGeneratesAndPersistsSecretWithSystemProperty() throws Exception {
        Path tempDir = Files.createTempDirectory("bflp-cluster-secret-test");
        HazelcastInstanceManager manager = new HazelcastInstanceManager();

        invokeEnsureClusterPassword(manager, tempDir);

        String generated = System.getProperty(PASSWORD_PROPERTY);
        assertThat(generated).isNotBlank();
        Path secretFile = tempDir.resolve("bflp-cluster-secret.properties");
        assertThat(secretFile).exists();

        if (isPosix(secretFile)) {
            Set<java.nio.file.attribute.PosixFilePermission> perms = Files.getPosixFilePermissions(secretFile);
            assertThat(perms).containsExactlyInAnyOrder(
                    java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                    java.nio.file.attribute.PosixFilePermission.OWNER_WRITE);
        }
    }

    @Test
    public void secondRunReadsBackSamePasswordRatherThanRegenerating() throws Exception {
        Path tempDir = Files.createTempDirectory("bflp-cluster-secret-test");

        HazelcastInstanceManager first = new HazelcastInstanceManager();
        invokeEnsureClusterPassword(first, tempDir);
        String firstPassword = System.getProperty(PASSWORD_PROPERTY);
        assertThat(firstPassword).isNotBlank();

        // Simulate a fresh JVM: clear the in-memory system property, but keep the secret file.
        System.clearProperty(PASSWORD_PROPERTY);
        HazelcastInstanceManager second = new HazelcastInstanceManager();
        invokeEnsureClusterPassword(second, tempDir);
        String secondPassword = System.getProperty(PASSWORD_PROPERTY);

        assertThat(secondPassword).isEqualTo(firstPassword);
    }

    @Test
    public void preSetPasswordPropertyIsNoOpAndDoesNotTouchSecretFile() throws Exception {
        Path tempDir = Files.createTempDirectory("bflp-cluster-secret-test");
        System.setProperty(PASSWORD_PROPERTY, "operator-provided-secret");
        HazelcastInstanceManager manager = new HazelcastInstanceManager();

        invokeEnsureClusterPassword(manager, tempDir);

        assertThat(System.getProperty(PASSWORD_PROPERTY)).isEqualTo("operator-provided-secret");
        assertThat(tempDir.resolve("bflp-cluster-secret.properties")).doesNotExist();
    }

    private static boolean isPosix(Path path) throws Exception {
        return Files.getFileAttributeView(path, PosixFileAttributeView.class) != null
                && Files.getFileStore(path).supportsFileAttributeView(PosixFileAttributeView.class);
    }

    // -------------------------------------------------------------------------------------------
    // mTLS keystore/truststore wiring
    // -------------------------------------------------------------------------------------------

    @Test
    public void configureTlsEnablesSslWhenKeystoreConfigured() throws Exception {
        System.setProperty(KEYSTORE_PROPERTY, "/path/to/keystore.jks");
        System.setProperty(KEYSTORE_PASSWORD_PROPERTY, "keystorepass");
        System.setProperty(TRUSTSTORE_PROPERTY, "/path/to/truststore.jks");
        System.setProperty(TRUSTSTORE_PASSWORD_PROPERTY, "truststorepass");
        HazelcastInstanceManager manager = new HazelcastInstanceManager();
        Config config = new Config();

        invokeConfigureTls(manager, config);

        com.hazelcast.config.SSLConfig ssl = config.getNetworkConfig().getSSLConfig();
        assertThat(ssl).isNotNull();
        assertThat(ssl.isEnabled()).isTrue();
        assertThat(ssl.getFactoryClassName()).isEqualTo("com.hazelcast.nio.ssl.BasicSSLContextFactory");
        assertThat(ssl.getProperty("keyStore")).isEqualTo("/path/to/keystore.jks");
        assertThat(ssl.getProperty("keyStorePassword")).isEqualTo("keystorepass");
        assertThat(ssl.getProperty("trustStore")).isEqualTo("/path/to/truststore.jks");
        assertThat(ssl.getProperty("trustStorePassword")).isEqualTo("truststorepass");
    }

    @Test
    public void configureTlsIsNoOpWhenNoKeystoreConfigured() throws Exception {
        HazelcastInstanceManager manager = new HazelcastInstanceManager();
        Config config = new Config();

        invokeConfigureTls(manager, config);

        com.hazelcast.config.SSLConfig ssl = config.getNetworkConfig().getSSLConfig();
        assertThat(ssl == null || !ssl.isEnabled()).isTrue();
    }
}
