package org.jahia.community.bruteforceloginprotection.hazelcast;

import org.jahia.community.bruteforceloginprotection.core.FailureWindow;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InvalidClassException;
import java.io.ObjectOutputStream;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.List;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * F28 — deserialization allowlist ({@link ClassLoaderAwareObjectInputStream}) and a pom/dependabot
 * scope-drift regression guard for the accepted-risk {@code hazelcast-all} dependency.
 */
public class ClassLoaderAwareObjectInputStreamTest {

    private static byte[] serialize(Object o) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(o);
        }
        return baos.toByteArray();
    }

    private static ClassLoaderAwareObjectInputStream openStream(byte[] bytes) throws Exception {
        return new ClassLoaderAwareObjectInputStream(
                Thread.currentThread().getContextClassLoader(), new ByteArrayInputStream(bytes));
    }

    @Test
    public void disallowedClassIsRejected() throws Exception {
        // java.io.File is Serializable but not on the allowlist (JDK types, module classes only).
        byte[] bytes = serialize(new File("/tmp/whatever"));

        try (ClassLoaderAwareObjectInputStream in = openStream(bytes)) {
            assertThatThrownBy(in::readObject).isInstanceOf(InvalidClassException.class);
        }
    }

    @Test
    public void jdkAllowlistedTypeSucceeds() throws Exception {
        HashMap<String, String> map = new HashMap<>();
        map.put("k", "v");
        byte[] bytes = serialize(map);

        try (ClassLoaderAwareObjectInputStream in = openStream(bytes)) {
            Object result = in.readObject();
            assertThat(result).isEqualTo(map);
        }
    }

    @Test
    public void moduleClassIsAllowedByPackagePrefix() throws Exception {
        FailureWindow window = new FailureWindow("1.2.3.4", "login");
        window.add(100L);
        byte[] bytes = serialize(window);

        try (ClassLoaderAwareObjectInputStream in = openStream(bytes)) {
            Object result = in.readObject();
            assertThat(result).isInstanceOf(FailureWindow.class);
            assertThat(((FailureWindow) result).getIp()).isEqualTo("1.2.3.4");
        }
    }

    /** Must be a concrete Serializable class (a lambda is not Serializable by default). */
    private static final class SerializableInvocationHandler implements InvocationHandler, java.io.Serializable {
        private static final long serialVersionUID = 1L;

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) {
            return null;
        }
    }

    @Test
    public void proxyClassAlwaysRejected() throws Exception {
        InvocationHandler handler = new SerializableInvocationHandler();
        Object proxy = Proxy.newProxyInstance(
                Thread.currentThread().getContextClassLoader(),
                new Class<?>[]{java.io.Serializable.class, Runnable.class},
                handler);
        byte[] bytes = serialize(proxy);

        try (ClassLoaderAwareObjectInputStream in = openStream(bytes)) {
            assertThatThrownBy(in::readObject).isInstanceOf(InvalidClassException.class);
        }
    }

    // -------------------------------------------------------------------------------------------
    // F28(a) — pom/dependabot scope-drift regression guard (lower-value per Stage 3's own
    // assessment, but cheap: catches an unnoticed scope change or a dropped ignore entry).
    // -------------------------------------------------------------------------------------------

    @Test
    public void hazelcastAllDependencyDeclaredAtProvidedScope() throws Exception {
        File pomFile = new File("pom.xml");
        assertThat(pomFile).exists();

        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        Document doc = factory.newDocumentBuilder().parse(pomFile);

        NodeList dependencyNodes = doc.getElementsByTagName("dependency");
        boolean found = false;
        for (int i = 0; i < dependencyNodes.getLength(); i++) {
            Element dep = (Element) dependencyNodes.item(i);
            String artifactId = textOf(dep, "artifactId");
            if ("hazelcast-all".equals(artifactId)) {
                found = true;
                assertThat(textOf(dep, "scope")).isEqualTo("provided");
            }
        }
        assertThat(found).as("hazelcast-all dependency must be declared in pom.xml").isTrue();
    }

    @Test
    public void dependabotIgnoresHazelcastAllVersionUpdates() throws Exception {
        File dependabotFile = new File(".github/dependabot.yml");
        assertThat(dependabotFile).exists();

        List<String> lines = Files.readAllLines(dependabotFile.toPath());
        boolean hasIgnoreEntry = lines.stream()
                .anyMatch(l -> l.contains("com.hazelcast:hazelcast-all"));

        assertThat(hasIgnoreEntry)
                .as("dependabot.yml must suppress version-update PRs for com.hazelcast:hazelcast-all")
                .isTrue();
    }

    private static String textOf(Element parent, String tagName) {
        NodeList nodes = parent.getElementsByTagName(tagName);
        if (nodes.getLength() == 0) {
            return null;
        }
        return nodes.item(0).getTextContent();
    }
}
