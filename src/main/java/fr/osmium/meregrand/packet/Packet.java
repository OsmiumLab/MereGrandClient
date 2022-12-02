package fr.osmium.meregrand.packet;

import java.io.Serial;
import java.io.Serializable;

public abstract class Packet implements Serializable {

    @Serial
    private static final long serialVersionUID = 1350092881346723535L;

    private final PacketType packetType;

    public Packet(PacketType packetType) {
        this.packetType = packetType;
    }

    public PacketType getType() {
        return packetType;
    }

    public enum PacketType {
        REQUEST_SERVER_KEY_PACKET, AUTH_PACKET, SEND_TOKEN_PACKET, SIGNED_CONTAINER_PACKET, ERROR_PACKET, PEAR_TO_PEAR_PACKET, EXCHANGE_PACKET
    }

}
