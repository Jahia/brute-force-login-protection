/*
 * Copyright (c) 2008-2020, Hazelcast, Inc. All Rights Reserved.
 * Licensed under the Apache License, Version 2.0 (the "License").
 */
package org.jahia.modules.bruteforceloginprotection.hazelcast;

import com.hazelcast.util.ConcurrentReferenceHashMap;

import java.lang.ref.WeakReference;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import static com.hazelcast.util.Preconditions.isNotNull;
import static java.util.Collections.unmodifiableMap;

public final class ClassLoaderUtil {

    private static final String HAZELCAST_BASE_PACKAGE = "com.hazelcast.";
    private static final String HAZELCAST_ARRAY = "[L" + HAZELCAST_BASE_PACKAGE;

    private static final boolean CLASS_CACHE_DISABLED = Boolean.getBoolean("hazelcast.compat.classloading.cache.disabled");

    private static final Map<String, Class<?>> PRIMITIVE_CLASSES;
    private static final int MAX_PRIM_CLASS_NAME_LENGTH = 7;

    private static final ClassLoaderWeakCache<Class<?>> CLASS_CACHE = new ClassLoaderWeakCache<>();

    static {
        final Map<String, Class<?>> primitives = new HashMap<>(10, 1.0f);
        primitives.put("boolean", boolean.class);
        primitives.put("byte", byte.class);
        primitives.put("int", int.class);
        primitives.put("long", long.class);
        primitives.put("short", short.class);
        primitives.put("float", float.class);
        primitives.put("double", double.class);
        primitives.put("char", char.class);
        primitives.put("void", void.class);
        PRIMITIVE_CLASSES = unmodifiableMap(primitives);
    }

    private ClassLoaderUtil() {
    }

    public static Class<?> loadClass(final ClassLoader classLoaderHint, final String className) throws ClassNotFoundException {
        isNotNull(className, "className");
        final Class<?> primitiveClass = tryPrimitiveClass(className);
        if (primitiveClass != null) {
            return primitiveClass;
        }
        ClassLoader theClassLoader = classLoaderHint;
        if (theClassLoader == null) {
            theClassLoader = Thread.currentThread().getContextClassLoader();
        }
        if (theClassLoader != null) {
            try {
                return tryLoadClass(className, theClassLoader);
            } catch (ClassNotFoundException ignore) {
                theClassLoader = null;
            }
        }
        if (className.startsWith(HAZELCAST_BASE_PACKAGE) || className.startsWith(HAZELCAST_ARRAY)) {
            theClassLoader = ClassLoaderUtil.class.getClassLoader();
        }
        if (theClassLoader == null) {
            theClassLoader = Thread.currentThread().getContextClassLoader();
        }
        if (theClassLoader != null) {
            return tryLoadClass(className, theClassLoader);
        }
        return Class.forName(className);
    }

    public static void flushCache() {
        CLASS_CACHE.clear();
    }

    private static Class<?> tryPrimitiveClass(String className) {
        if (className.length() <= MAX_PRIM_CLASS_NAME_LENGTH && Character.isLowerCase(className.charAt(0))) {
            final Class<?> primitiveClass = PRIMITIVE_CLASSES.get(className);
            if (primitiveClass != null) {
                return primitiveClass;
            }
        }
        return null;
    }

    private static Class<?> tryLoadClass(String className, ClassLoader classLoader) throws ClassNotFoundException {
        Class<?> clazz;
        if (!CLASS_CACHE_DISABLED) {
            clazz = CLASS_CACHE.get(classLoader, className);
            if (clazz != null) {
                return clazz;
            }
        }
        if (className.startsWith("[")) {
            clazz = Class.forName(className, false, classLoader);
        } else {
            clazz = classLoader.loadClass(className);
        }
        if (!CLASS_CACHE_DISABLED) {
            CLASS_CACHE.put(classLoader, className, clazz);
        }
        return clazz;
    }

    private static final class ClassLoaderWeakCache<V> {
        private final ConcurrentMap<ClassLoader, ConcurrentMap<String, WeakReference<V>>> cache;

        private ClassLoaderWeakCache() {
            cache = new ConcurrentReferenceHashMap<>(16);
        }

        private void put(ClassLoader classLoader, String className, V value) {
            ClassLoader cl = classLoader == null ? ClassLoaderUtil.class.getClassLoader() : classLoader;
            ConcurrentMap<String, WeakReference<V>> innerCache = cache.get(cl);
            if (innerCache == null) {
                innerCache = new ConcurrentHashMap<>(100);
                ConcurrentMap<String, WeakReference<V>> old = cache.putIfAbsent(cl, innerCache);
                if (old != null) {
                    innerCache = old;
                }
            }
            innerCache.put(className, new WeakReference<>(value));
        }

        public V get(ClassLoader classloader, String className) {
            isNotNull(className, "className");
            ConcurrentMap<String, WeakReference<V>> innerCache = cache.get(classloader);
            if (innerCache == null) {
                return null;
            }
            WeakReference<V> reference = innerCache.get(className);
            V value = reference == null ? null : reference.get();
            if (reference != null && value == null) {
                innerCache.remove(className);
            }
            return value;
        }

        public void clear() {
            cache.clear();
        }
    }
}
