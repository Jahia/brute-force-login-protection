package org.jahia.modules.bruteforceloginprotection.hazelcast;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.lang.reflect.Modifier;
import java.lang.reflect.Proxy;
import java.util.Arrays;

public class ClassLoaderAwareObjectInputStream extends ObjectInputStream {

    private final ClassLoader classLoader;

    public ClassLoaderAwareObjectInputStream(final ClassLoader classLoader, final InputStream in) throws IOException {
        super(in);
        this.classLoader = classLoader;
    }

    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) throws ClassNotFoundException {
        String name = desc.getName();
        try {
            return ClassLoaderUtil.loadClass(classLoader, name);
        } catch (ClassNotFoundException ex) {
            throw new ClassNotFoundException("Unable to deserialize, class not found: " + name, ex);
        }
    }

    @Override
    protected Class<?> resolveProxyClass(String[] interfaces) throws ClassNotFoundException {
        ClassLoader nonPublicLoader = null;
        Class<?>[] classObjs = new Class<?>[interfaces.length];
        for (int i = 0; i < interfaces.length; i++) {
            Class<?> cl = ClassLoaderUtil.loadClass(classLoader, interfaces[i]);
            if ((cl.getModifiers() & Modifier.PUBLIC) == 0) {
                if (nonPublicLoader != null) {
                    if (nonPublicLoader != cl.getClassLoader()) {
                        throw new IllegalAccessError("conflicting non-public interface class loaders, for Class: " + cl.getName());
                    }
                } else {
                    nonPublicLoader = cl.getClassLoader();
                }
            }
            classObjs[i] = cl;
        }
        try {
            return Proxy.getProxyClass(nonPublicLoader != null ? nonPublicLoader : classLoader, classObjs);
        } catch (IllegalArgumentException e) {
            throw new ClassNotFoundException("Error resolving proxy class for interfaces: " + Arrays.toString(interfaces), e);
        }
    }
}
