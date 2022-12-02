package fr.osmium.meregrand.packet;

import java.security.interfaces.RSAPublicKey;

public class ExchangeKeyPacket extends Packet {

    private final RSAPublicKey publicKey;

    public ExchangeKeyPacket(RSAPublicKey publicKey) {
        super(PacketType.EXCHANGE_PACKET);
        this.publicKey = publicKey;
    }

    public RSAPublicKey getPublicKey() {
        return publicKey;
    }

}
