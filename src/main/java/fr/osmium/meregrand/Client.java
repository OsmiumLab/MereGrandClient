package fr.osmium.meregrand;

import fr.osmium.meregrand.cipher.ICipher;
import fr.osmium.meregrand.cipher.RSA;
import fr.osmium.meregrand.cipher.SHA256;
import fr.osmium.meregrand.packet.*;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.interfaces.RSAPublicKey;
import java.util.Scanner;
import java.util.logging.Logger;

public class Client {

    private final static Logger LOGGER = Logger.getLogger("MereGrandClient");

    private final static int PORT = 6969;

    private final static String HOSTNAME = "localhost";

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
            out.writeObject(authPacket);

            switch (in.readObject()) {
                case FailAuthPacket failAuthPacket -> LOGGER.warning(failAuthPacket.getErrorMessage());
                case SendTokenPacket sendTokenPacket -> {
                    final Socket targetSocket = new Socket(sendTokenPacket.getIp(), 6969);
                    ObjectOutputStream targetOut = new ObjectOutputStream(targetSocket.getOutputStream());
                    ObjectInputStream targetIn = new ObjectInputStream(targetSocket.getInputStream());
                    PearToPearPacket pearToPearPacket = new PearToPearPacket(cipher.cipher(message, sendTokenPacket.getPublicKey()), sendTokenPacket.getToken());
                    targetOut.writeObject(pearToPearPacket);
                    targetSocket.close();
                }
                case null, default -> LOGGER.warning("Unknown packet");
            }

            socket.close();

        } catch (IOException | ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    private void getServerKey () throws IOException, ClassNotFoundException {
        out.writeObject(new RequestServerKeyPacket());
        ExchangeKeyPacket exchangeKeyPacket = (ExchangeKeyPacket) in.readObject();
        serverPublicKey = exchangeKeyPacket.getPublicKey();
    }

}
