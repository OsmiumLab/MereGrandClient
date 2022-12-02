package fr.osmium.meregrand;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
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
import java.util.Base64;
import java.util.Scanner;
import java.util.logging.Logger;

public class Client {

    private final static Logger LOGGER = Logger.getLogger("MereGrandClient");

    private final static int PORT = 6968;

    private final static String HOSTNAME = "localhost";

    private final ICipher cipher = new RSA(2048);

    private final ObjectOutputStream out;
    private final ObjectInputStream in;

    private RSAPublicKey serverPublicKey;

    public Client() {
        try {
            ServerSocket socketServer = new ServerSocket(PORT);
            final Socket socket = new Socket(HOSTNAME, PORT);
            LOGGER.info("Client connected !");

            out = new ObjectOutputStream(socket.getOutputStream());
            in = new ObjectInputStream(socket.getInputStream());

            getServerKey();

            final Scanner scanner = new Scanner(System.in);
            System.out.println("Enter your email : ");
            String message = scanner.nextLine();
            final String email = scanner.next();
            String password = scanner.next();
            final String targetMail = scanner.next();

            message = SHA256.hash(message);
            password = cipher.cipher(password, serverPublicKey);

            final AuthPacket authPacket = new AuthPacket(email, password, message, targetMail);
            out.writeObject(authPacket);
            Socket s1 = socketServer.accept();
            if(s1 != null) {
                final ObjectInputStream objectInputStream = new ObjectInputStream(s1.getInputStream());
                final ObjectOutputStream objectOutputStream = new ObjectOutputStream(s1.getOutputStream());
                if (objectInputStream.readObject() instanceof PearToPearPacket pearToPearPacket) {
                    final String[] splitString = pearToPearPacket.getToken().split("\\.");
                    final String base64EncodedBody = splitString[1];
                    final String base64EncodedSignature = splitString[2];
                    final String decryptedMessage = new String(cipher.decipher(pearToPearPacket.getMessage()));
                    final String body = new String(Base64.getUrlDecoder().decode(base64EncodedBody));
                    final Gson gson = new GsonBuilder().disableHtmlEscaping().create();
                    TokenData tokenData = gson.fromJson(body, TokenData.class);
                    if (tokenData.getHash().equals(SHA256.hash(decryptedMessage)))
                        objectOutputStream.writeObject(new ErrorPacket("Wrong hash"));
                }
            }
            final Object object = in.readObject();
            if (object instanceof ErrorPacket errorPacket) {
                LOGGER.warning(errorPacket.getErrorMessage());
            } else if (object instanceof SendTokenPacket sendTokenPacket) {
                final Socket targetSocket = new Socket(sendTokenPacket.getIp(), PORT);
                ObjectOutputStream targetOut = new ObjectOutputStream(targetSocket.getOutputStream());
                ObjectInputStream targetIn = new ObjectInputStream(targetSocket.getInputStream());
                PearToPearPacket pearToPearPacket = new PearToPearPacket(cipher.cipher(message, sendTokenPacket.getPublicKey()), sendTokenPacket.getToken());
                targetOut.writeObject(pearToPearPacket);
                targetSocket.close();
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
