package fr.osmium.meregrand.packet;

public class PearToPearPacket extends Packet {

    private final String message;
    private final String token;

    public PearToPearPacket(String message, String token) {
        super(PacketType.PEAR_TO_PEAR_PACKET);
        this.message = message;
        this.token = token;
    }

    public String getMessage() {
        return message;
    }

    public String getToken() {
        return token;
    }
}
