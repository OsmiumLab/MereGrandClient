package fr.osmium.meregrand.cipher;

public interface ICipher {

    String cipher(String message);
    String decipher(String message);

    String getPublicKey();

    String getPrivateKey();

}
