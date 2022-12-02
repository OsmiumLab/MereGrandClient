package fr.osmium.meregrand;

public class TokenData {

    public final String publicKey;
    public final String email;
    public final String hash;

    public TokenData(String publicKey, String email, String hash) {
        this.publicKey = publicKey;
        this.email = email;
        this.hash = hash;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public String getEmail() {
        return email;
    }

    public String getHash() {
        return hash;
    }
}
