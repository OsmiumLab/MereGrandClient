package fr.osmium.meregrand.cipher;

import fr.osmium.meregrand.utils.ByteUtils;

import java.security.InvalidKeyException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class Signature {

    private static Signature instance;

    private final java.security.Signature signature;

    private final RSAPrivateKey privateKey;
    private final RSAPublicKey publicKey;

    public Signature(RSAPrivateKey privateKey, RSAPublicKey publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        try {
            signature = java.security.Signature.getInstance("SHA256withDSA");
            signature.initSign(privateKey);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public byte[] sign(Object object) {
        try {
            signature.update(ByteUtils.serialize(object));
            return signature.sign();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static Signature getInstance() {
        return instance;
    }
}
