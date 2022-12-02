package fr.osmium.meregrand.packet;

public class SignedContainerPacket extends Packet {

    private final AuthPacket authPacket;
    private final byte[] signature;

    public SignedContainerPacket(AuthPacket authPacket, byte[] signature) {
        super(PacketType.SIGNED_CONTAINER_PACKET);
        this.authPacket = authPacket;
        this.signature = signature;
    }

    public AuthPacket getAuthPacket() {
        return authPacket;
    }

    public byte[] getSignature() {
        return signature;
    }
}
