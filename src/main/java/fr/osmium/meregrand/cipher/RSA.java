package fr.osmium.meregrand.cipher;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class RSA implements ICipher {

    private BigInteger modulus;
    private BigInteger privateKey;
    private BigInteger publicKey;

    public RSA(int bits) {
        generateKeys(bits);
    }

    public synchronized void generateKeys(int bits) {
        final SecureRandom r = new SecureRandom();
        final BigInteger p = new BigInteger(bits / 2, 100, r);
        final BigInteger q = new BigInteger(bits / 2, 100, r);
        modulus = p.multiply(q);

        final BigInteger m = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));

        publicKey = BigInteger.valueOf(3L);

        while (m.gcd(publicKey).intValue() > 1)
            publicKey = publicKey.add(BigInteger.valueOf(2L));
        privateKey = publicKey.modInverse(m);
    }

    @Override
    public String cipher(String message) {
        return (new BigInteger(message.getBytes(StandardCharsets.UTF_8))).modPow(publicKey, modulus).toString();
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
