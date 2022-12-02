package fr.osmium.meregrand.packet;

public class AuthPacket extends Packet {

    private final String email;
    private final String password;
    private final String messageHash;

    public AuthPacket(String messageHash, String email, String password, String targetMail) {
        super(PacketType.AUTH_PACKET);
        this.email = email;
        this.password = password;
        this.messageHash = messageHash;
    }

    public String getEmail() {
        return email;
    }

    public String getPassword() {
        return password;
    }

    public String getMessage() {
        return messageHash;
    }
}
