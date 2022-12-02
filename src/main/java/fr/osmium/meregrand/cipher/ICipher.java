package fr.osmium.meregrand.cipher;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public interface ICipher {

    String cipher(String message, RSAPublicKey publicKey);
    String cipher(byte[] bytes, RSAPublicKey publicKey);
    byte[] decipher(String message);

    RSAPublicKey getPublicKey();
    RSAPrivateKey getPrivateKey();

}
