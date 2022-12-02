package fr.osmium.meregrand.utils;

import java.io.*;

public class ByteUtils {

    public static byte[] serialize(Object obj) throws IOException {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        final ObjectOutputStream os = new ObjectOutputStream(out);
        os.writeObject(obj);
        byte[] bytes = out.toByteArray();
        os.close();
        out.close();
        return bytes;
    }
    public static Object deserialize(byte[] data) throws IOException, ClassNotFoundException {
        final ByteArrayInputStream in = new ByteArrayInputStream(data);
        final ObjectInputStream is = new ObjectInputStream(in);
        Object object = is.readObject();
        in.close();
        is.close();
        return object;
    }

}
