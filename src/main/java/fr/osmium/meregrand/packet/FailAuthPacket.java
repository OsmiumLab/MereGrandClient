package fr.osmium.meregrand.packet;

public class FailAuthPacket extends Packet {

    private final String errorMessage;

    public FailAuthPacket(String errorMessage) {
        super(PacketType.FAIL_AUTH_PACKET);
        this.errorMessage = errorMessage;
    }

    public String getErrorMessage() {
        return errorMessage;
    }
}
