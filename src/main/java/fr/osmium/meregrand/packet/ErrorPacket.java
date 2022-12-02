package fr.osmium.meregrand.packet;

public class ErrorPacket extends Packet {

    private final String errorMessage;

    public ErrorPacket(String errorMessage) {
        super(PacketType.ERROR_PACKET);
        this.errorMessage = errorMessage;
    }

    public String getErrorMessage() {
        return errorMessage;
    }
}
