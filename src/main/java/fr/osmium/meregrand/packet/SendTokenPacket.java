package fr.osmium.meregrand.packet;

public class SendTokenPacket extends Packet {

    private final String publicKey;
    private final String token;

    public SendTokenPacket(String token, String publicKey) {
        super(PacketType.SEND_TOKEN_PACKET);
        this.token = token;
        this.publicKey = publicKey;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public String getToken() {
        return token;
    }
}
