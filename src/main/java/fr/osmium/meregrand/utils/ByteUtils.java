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
    public static <T> T deserialize(byte[] data, Class<T> clazz) throws IOException, ClassNotFoundException {
        final ByteArrayInputStream in = new ByteArrayInputStream(data);
        final ObjectInputStream is = new ObjectInputStream(in);
        T object = clazz.cast(is.readObject());
        in.close();
        is.close();
        return object;
    }

}
