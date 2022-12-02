package fr.osmium.meregrand;

import fr.osmium.meregrand.cipher.ICipher;
import fr.osmium.meregrand.cipher.RSA;
import fr.osmium.meregrand.cipher.SHA256;
import fr.osmium.meregrand.packet.AuthPacket;
import fr.osmium.meregrand.packet.ExchangeKeyPacket;
import fr.osmium.meregrand.packet.RequestServerKeyPacket;
import fr.osmium.meregrand.packet.SendTokenPacket;
import fr.osmium.meregrand.utils.ByteUtils;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.interfaces.RSAPublicKey;
import java.util.Scanner;
import java.util.logging.Logger;

public class Client {

    private final static Logger LOGGER = Logger.getLogger("MereGrandClient");

    private final static String HOSTNAME = "localhost";

    private final static int PORT = 6969;

    private final ICipher cipher = new RSA(2048);

    private final ObjectOutputStream out;
    private final ObjectInputStream in;

    private RSAPublicKey serverPublicKey;

    public Client() {
        try {
            final Socket socket = new Socket(HOSTNAME, PORT);
            LOGGER.info("Client connected !");

            out = new ObjectOutputStream(socket.getOutputStream());
            in = new ObjectInputStream(socket.getInputStream());

            getServerKey();

            Scanner scanner = new Scanner(System.in);
            String message = scanner.nextLine();
            final String email = scanner.next();
            String password = scanner.next();
            final String targetMail = scanner.next();

            message = SHA256.hash(message);
            password = cipher.cipher(password, serverPublicKey);

            final AuthPacket authPacket = new AuthPacket(email, password, message, targetMail);
            out.writeObject(cipher.cipher(ByteUtils.serialize(authPacket), serverPublicKey));

            SendTokenPacket sendTokenPacket = (SendTokenPacket) in.readObject();
            // send packet to c2


            socket.close();

        } catch (IOException | ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    private void getServerKey() throws IOException, ClassNotFoundException {
        out.writeObject(new RequestServerKeyPacket());
        ExchangeKeyPacket exchangeKeyPacket = (ExchangeKeyPacket) in.readObject();
        serverPublicKey = exchangeKeyPacket.getPublicKey();
    }

}
