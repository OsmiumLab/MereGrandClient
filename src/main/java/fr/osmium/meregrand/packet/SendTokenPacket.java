package fr.osmium.meregrand.packet;

import java.security.interfaces.RSAPublicKey;

public class SendTokenPacket extends Packet {

    private final RSAPublicKey publicKey;
    private final String token;
    private final String ip;

    public SendTokenPacket(RSAPublicKey publicKey, String token, String ip) {
        super(PacketType.SEND_TOKEN_PACKET);
        this.publicKey = publicKey;
        this.token = token;
        this.ip = ip;
    }

    public RSAPublicKey getPublicKey() {
        return publicKey;
    }

    public String getToken() {
        return token;
    }

    public String getIp() {
        return ip;
    }
}
