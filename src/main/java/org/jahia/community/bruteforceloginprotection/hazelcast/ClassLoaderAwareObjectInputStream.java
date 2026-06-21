package org.jahia.community.bruteforceloginprotection.hazelcast;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Hardened {@link ObjectInputStream} used by the Hazelcast serializer.
 *
 * <p>In addition to using the module's classloader for class resolution, this stream restricts
 * the classes that can be deserialized to a tight allowlist to mitigate Java-deserialization
 * gadget attacks. Anything outside the allowlist is rejected with {@link InvalidClassException}.
 * Proxy classes are rejected outright.</p>
 */
public class ClassLoaderAwareObjectInputStream extends ObjectInputStream {

    private static final Logger LOGGER = LoggerFactory.getLogger(ClassLoaderAwareObjectInputStream.class);

    private static final String MODULE_PACKAGE_PREFIX = "org.jahia.community.bruteforceloginprotection.";

    private static final Set<String> JDK_ALLOWLIST;
    static {
        Set<String> s = new HashSet<>();
        // Strings, primitive wrappers
        s.add("java.lang.String");
        s.add("java.lang.Number");
        s.add("java.lang.Long");
        s.add("java.lang.Integer");
        s.add("java.lang.Double");
        s.add("java.lang.Float");
        s.add("java.lang.Short");
        s.add("java.lang.Byte");
        s.add("java.lang.Boolean");
        s.add("java.lang.Character");
        // enum constants resolve to their concrete subclass; the module-prefix check covers them
        // Collections
        s.add("java.util.ArrayList");
        s.add("java.util.LinkedList");
        s.add("java.util.HashMap");
        s.add("java.util.LinkedHashMap");
        s.add("java.util.HashSet");
        s.add("java.util.LinkedHashSet");
        s.add("java.util.TreeMap");
        s.add("java.util.TreeSet");
        s.add("java.util.ArrayDeque"); // FailureWindow stores failure timestamps in an ArrayDeque
        // Time/identity
        s.add("java.util.Date");
        s.add("java.time.Instant");
        s.add("java.util.UUID");
        JDK_ALLOWLIST = Collections.unmodifiableSet(s);
    }

    private final ClassLoader classLoader;

    public ClassLoaderAwareObjectInputStream(final ClassLoader classLoader, final InputStream in) throws IOException {
        super(in);
        this.classLoader = classLoader;
    }

    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) throws ClassNotFoundException, IOException {
        String name = desc.getName();
        if (!isAllowed(name)) {
            if (LOGGER.isWarnEnabled()) {
                LOGGER.warn("BFLP: refusing to deserialize disallowed class '{}'", name.replaceAll("[\r\n]", ""));
            }
            throw new InvalidClassException(name, "Class not allowed for deserialization");
        }
        try {
            return ClassLoaderUtil.loadClass(classLoader, name);
        } catch (ClassNotFoundException ex) {
            throw new ClassNotFoundException("Unable to deserialize, class not found: " + name, ex);
        }
    }

    /**
     * Reject all dynamic proxy classes — deserializing arbitrary proxy interface tuples is a
     * well-known gadget pivot, and the module's own value types are never proxies.
     */
    @Override
    protected Class<?> resolveProxyClass(String[] interfaces) throws IOException {
        LOGGER.warn("BFLP: refusing to deserialize proxy class (interfaces={})", interfaces == null ? 0 : interfaces.length);
        throw new InvalidClassException("Proxy classes are not allowed for deserialization");
    }

    private static boolean isAllowed(String name) {
        if (name == null || name.isEmpty()) {
            return false;
        }
        // Arrays — peel the leading '[' / 'L' wrapper(s) until we reach an actual type name.
        String t = name;
        while (t.startsWith("[")) {
            t = t.substring(1);
        }
        if (t.startsWith("L") && t.endsWith(";")) {
            t = t.substring(1, t.length() - 1);
        } else if (t.length() == 1) {
            // primitive array element type code (Z, B, C, D, F, I, J, S) — always safe
            return "ZBCDFIJS".indexOf(t.charAt(0)) >= 0;
        }
        if (t.startsWith(MODULE_PACKAGE_PREFIX)) {
            return true;
        }
        if (JDK_ALLOWLIST.contains(t)) {
            return true;
        }
        // Collections$* immutable wrapper inner classes
        return t.startsWith("java.util.Collections$") || t.startsWith("java.util.ImmutableCollections$");
    }
}
