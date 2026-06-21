package org.jahia.community.bruteforceloginprotection.hazelcast;

import com.hazelcast.nio.ObjectDataInput;
import com.hazelcast.nio.ObjectDataOutput;
import com.hazelcast.nio.serialization.StreamSerializer;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;

public class ClassLoaderAwareSerializer implements StreamSerializer<Object> {

    @Override
    public void write(ObjectDataOutput out, Object object) throws IOException {
        ObjectOutputStream objectOutputStream = new ObjectOutputStream((OutputStream) out);
        objectOutputStream.writeObject(object);
        objectOutputStream.flush();
    }

    @Override
    public Object read(ObjectDataInput in) throws IOException {
        try (ObjectInputStream ois = new ClassLoaderAwareObjectInputStream(in.getClassLoader(), (InputStream) in)) {
            return ois.readObject();
        } catch (Exception e) {
            throw new IOException(e);
        }
    }

    @Override
    public int getTypeId() {
        return 2;
    }

    @Override
    public void destroy() {
        // Nothing to do
    }
}
