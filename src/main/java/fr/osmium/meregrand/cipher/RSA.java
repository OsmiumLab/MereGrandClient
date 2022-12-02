package fr.osmium.meregrand.cipher;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class RSA implements ICipher {

    private RSAPrivateKey privateKey;
    private RSAPublicKey publicKey;

    public RSA(int bits) {
        generateKeys(bits);
    }

    public synchronized void generateKeys(int bits) {
        try {
            final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(bits);
            final KeyPair kp = kpg.generateKeyPair();
            privateKey = (RSAPrivateKey) kp.getPrivate();
            publicKey = (RSAPublicKey) kp.getPublic();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public String cipher(String message, RSAPublicKey publicKey) {
        return cipher(message.getBytes(StandardCharsets.UTF_8), publicKey);
    }

    @Override
    public String cipher(byte[] bytes, RSAPublicKey publicKey) {
        return (new BigInteger(bytes).modPow(new BigInteger(publicKey.getEncoded()), publicKey.getModulus()).toString());
    }

    @Override
    public byte[] decipher(String message) {
        return new BigInteger(message.getBytes(StandardCharsets.UTF_8)).modPow(privateKey.getPrivateExponent(), privateKey.getModulus()).toByteArray();
    }

    @Override
    public RSAPublicKey getPublicKey() {
        return publicKey;
    }

    @Override
    public RSAPrivateKey getPrivateKey() {
        return privateKey;
    }
}
