package fr.osmium.meregrand.packet;

public class ExchangePacket extends Packet {

    private final String publicKey;

    public ExchangePacket(String publicKey) {
        super(PacketType.EXCHANGE_PACKET);
        this.publicKey = publicKey;

    };

    public String getPublicKey() {
        return publicKey;
    }

}
