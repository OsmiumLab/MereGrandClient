package fr.osmium.meregrand.cipher;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class RSA implements ICipher {

    private BigInteger modulus;
    private BigInteger privateKey;
    private BigInteger publicKey;

    public RSA(int bits) {
        generateKeys(bits);
    }

    public synchronized void generateKeys(int bits) {
        try {
            final KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(bits);
            final KeyPair kp = kpg.generateKeyPair();
            privateKey = new BigInteger(kp.getPrivate().getEncoded());
            publicKey = new BigInteger(kp.getPublic().getEncoded());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public String cipher(String message, String publicKey) {
        return (new BigInteger(message.getBytes(StandardCharsets.UTF_8))).modPow(new BigInteger(publicKey), modulus).toString();
    }

    @Override
    public String decipher(String message) {
        return new String((new BigInteger(message)).modPow(privateKey, modulus).toByteArray());
    }

    @Override
    public String getPublicKey() {
        return publicKey.toString();
    }

    @Override
    public String getPrivateKey() {
        return privateKey.toString();
    }
}
