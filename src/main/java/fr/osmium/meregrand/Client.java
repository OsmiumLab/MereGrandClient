package fr.osmium.meregrand;

import fr.osmium.meregrand.cipher.ICipher;
import fr.osmium.meregrand.cipher.RSA;
import fr.osmium.meregrand.packet.AuthPacket;
import fr.osmium.meregrand.packet.ExchangePacket;
import fr.osmium.meregrand.packet.RequestServerKeyPacket;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;
import java.util.logging.Logger;

public class Client {

    private final static Logger LOGGER = Logger.getLogger("MereGrandClient");

    private final static String HOSTNAME = "localhost";

    private final static int PORT = 6969;

    private final ICipher cipher = new RSA(2048);

    private final ObjectOutputStream out;
    private final ObjectInputStream in;

    private String serverPublicKey;

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

            final MessageDigest md = MessageDigest.getInstance("SHA-256");
            message = new String(md.digest(message.getBytes(StandardCharsets.UTF_8)));
            password = new String(md.digest(password.getBytes(StandardCharsets.UTF_8)));

            AuthPacket authPacket = new AuthPacket(email, password, message, targetMail);
            out.writeObject(cipher.cipher(message, serverPublicKey));

            String response = (String) in.readObject();
            LOGGER.info("Server response: " + cipher.decipher(response));
            // Le client C1 est désormais libre d'envoyer a qu'il le souhaite son message, par exemple à C2;
            socket.close();

        } catch (IOException | ClassNotFoundException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private void getServerKey() throws IOException, ClassNotFoundException {
        out.writeObject(new RequestServerKeyPacket());
        ExchangePacket exchangePacket = (ExchangePacket) in.readObject();
        serverPublicKey = exchangePacket.getPublicKey();
    }

}
