package fr.osmium.meregrand;

import fr.osmium.meregrand.cipher.ICipher;
import fr.osmium.meregrand.cipher.RSA;
import fr.osmium.meregrand.packet.ExchangePacket;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
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

            swapPublicKeys();
//            Scanner scanner = new Scanner(System.in);
//            while (true) {
//                String message = scanner.nextLine();
//                out.writeObject(cipher.cipher(message, serverPublicKey));
//                String response = (String) in.readObject();
//                LOGGER.info("Server response: " + cipher.decipher(response));
//                // Le client C1 est désormais libre d'envoyer a qu'il le souhaite son message, par exemple à C2;
//            }
            socket.close();
        } catch (IOException | ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    private void swapPublicKeys() throws IOException, ClassNotFoundException {
        out.writeObject(new ExchangePacket(cipher.getPublicKey()));
        ExchangePacket exchangePacket = (ExchangePacket) in.readObject();
        serverPublicKey = exchangePacket.getPublicKey();
    }

}
