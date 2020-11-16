//File: ClientMain.java
//Purpose: Main class for Client SENG2250 assignment 3 - Task 2
//Programmer: Liam Craft - C3339847
//Date:10/11/2020

import java.math.BigInteger;
import java.io.*;
import java.net.*;
import java.util.Base64;

public class ClientMain {
    public static void main(String[] args) {
        Client c = new Client();
        try{
            Socket cSocket = new Socket("localHost", 6969);
            PrintWriter out = new PrintWriter(cSocket.getOutputStream(), true);
            BufferedReader in = new BufferedReader(new InputStreamReader(cSocket.getInputStream()));
            //input/output message strings
            //String fromServer, toServer;
            System.out.println("----------------");
            System.out.println("***Setup Phase***");
            System.out.println("-----------------");
            System.out.println("Waiting on input.....");
            //client to server - "Hello" will initiate the setup phase
            c.setToServer(System.console().readLine());
            //send init msg to server
            out.println(c.getToServer());
            System.out.println();
            System.out.println("---------->");
            System.out.println("Client to server: " + c.getToServer());
            //get response from server - loop until proper init message "Hello" is sent. Just for giggles
            c.setFromServer(in.readLine());
            while(!c.getFromServer().equalsIgnoreCase("Connection established")){
                System.out.println(c.getFromServer());
                System.out.println("Waiting on input.....");
                c.setToServer(System.console().readLine());

                out.println(c.getToServer());
                c.setFromServer(in.readLine());
            }
            c.setInitMsg(c.getToServer());
            System.out.println("---------->");
            System.out.println();
            System.out.println("<----------");
            System.out.println("Server response: " + c.getFromServer());
            //fromServer = in.readLine();
            //server responds with it's RSA public key
            //pubkey - e
            //key and sig vars
            BigInteger[] serverRSAKey = c.getServerRSAKey();
            BigInteger serverRSASig = c.getServerRSASig();
            //
            serverRSAKey[0] = new BigInteger(in.readLine());
            //n
            serverRSAKey[1] = new BigInteger(in.readLine());
            //Client responds with it's ID
            System.out.println("Server to client: RSA_PK =  \n" + serverRSAKey[0] + " + " + serverRSAKey[1]);
            serverRSASig = new BigInteger(in.readLine());
            System.out.println("<----------");
            System.out.println();
            System.out.println("Client: Verifying RSA signature....");
            if(Utilities.verifyRSA(c.getInitMsg(), serverRSASig, serverRSAKey[0], serverRSAKey[1])){
                //server verified
                System.out.println("Server verified");
            }
            else{
                //Server not verified- close?
                System.out.println("Server verification failed. Closing....");
                System.exit(1);
            }
            System.out.println();

            //****Handshake phase****
            System.out.println("----------------");
            System.out.println("Handshake Phase");
            System.out.println("----------------");
            //TODO: Send and receive id's
            //send client id
            out.println(c.getClientID());
            //receive server id
            c.setCurrentServerId(in.readLine());
            System.out.println("---------->");
            System.out.println("CLient to server:");
            System.out.println("Client ID: " + c.getClientID());
            System.out.println("---------->");
            System.out.println();
            System.out.println("<----------");
            System.out.println("Server to client:");
            System.out.println("Server ID: " + c.getCurrentServerId());
            System.out.println("<----------");
            System.out.println();

            //***DH key exchange***
            //Send DH public key to server
            out.println(c.getClientPubDHKey());
            System.out.println("---------->");
            System.out.println("CLient to server:");
            System.out.println("DH public key: \n" + c.getClientPubDHKey());
            //receive server DH public key
            c.setServerPubDHKey(new BigInteger(in.readLine()));
            System.out.println("---------->");
            System.out.println();
            System.out.println("<----------");
            System.out.println("Server to client:");
            System.out.println("Received DH public key: \n" + c.getServerPubDHKey());
            System.out.println("<----------");
            System.out.println();
            //calc DH session key
            c.setSessionKey(Utilities.calcDHSessionKey(c.getServerPubDHKey(), c.getClientPrivDHKey()));
            //send IV to server
            System.out.println("---------->");
            out.println(Base64.getEncoder().encodeToString(c.getInitVector()));
            c.setToServer(Base64.getEncoder().encodeToString(Utilities.CBCEncrypt(c.getClientChallengeStr(), c.getSessionKey(), c.getInitVector())));
            out.println(c.getToServer());
            System.out.println("Challenge sent to server");
            System.out.println("Agreed encrypted message?: " + c.getToServer());
            System.out.println("---------->");
            //receive servers challenge response
            System.out.println();
            System.out.println("<----------");
            System.out.println("Server - Challenge response");
            c.setChallengeResponse(Base64.getDecoder().decode(in.readLine()));
            System.out.println("Agreed encrypted message?: " + c.getToServer());
            System.out.println("<----------");
            System.out.println();
            System.out.println("Checking server session key....");
            if(Utilities.sesKeyMsgCheck(Utilities.CBCDecrypt(c.getChallengeResponse(), c.getSessionKey(), c.getInitVector()), c.getClientChallengeStr())){
                System.out.println("Server session key verified.");
            }
            else{
                System.out.println("Error: Server session key verification failed.");
                System.exit(1);
            }
            System.out.println();

            System.out.println();
            System.out.println("----------------");
            //****data exchange****
            byte[] encryptedMsgOut, encryptedMsgIn;
            String HMACTagOut = "", HMACTagIn = "";
            System.out.println("****Data exchange****");
            System.out.println("----------------");
            //client sends encrypted text to server (2 exchanges) - ensure each is 64 bytes
            //*SEND* (message and HMAC tag)
            //create messages
            c.setToServer("Confidentiality-Preserving authorized restrictions on info******"); //64 bytes
            encryptedMsgOut = Utilities.CBCEncrypt(c.getToServer(), c.getSessionKey(), c.getInitVector());
            HMACTagOut = Utilities.genHMAC(c.getSessionKey(), c.getToServer()).toString();
            //send messages
            out.println(Base64.getEncoder().encodeToString(encryptedMsgOut));
            out.println(HMACTagOut);
            System.out.println("---------->");
            System.out.println("Client to Server: ");
            System.out.println("PlainText message: " + c.getToServer());
            System.out.println("Encrypted message: " + new String(encryptedMsgOut));
            System.out.println("HMAC tag: " + HMACTagOut);
            System.out.println("---------->");
            System.out.println();
            //*RECEIVE*
            encryptedMsgIn = Base64.getDecoder().decode(in.readLine());
            HMACTagIn = in.readLine();
            c.setFromServer(Utilities.CBCDecrypt(encryptedMsgIn, c.getSessionKey(), c.getInitVector()));
            System.out.println("<----------");
            System.out.println("Server to Client: ");
            System.out.println("Encrypted message: " + new String(encryptedMsgIn));
            //verify HMAC tag- close if false
            if(!Utilities.verifyHMAC(c.getSessionKey(), c.getFromServer(), new BigInteger(HMACTagIn))){
                System.out.println("System has detected a bad HMAC. Closing connection....");
                cSocket.close();
            }
            else{
                System.out.println("HMAC verified. Decrypting....");
            }
            System.out.println("Plaintext message: " + Utilities.CBCDecrypt(encryptedMsgIn, c.getSessionKey(), c.getInitVector()));
            System.out.println("<----------");
            System.out.println();
            //*SEND*
            c.setToServer("Availability- Ensuring timely and reliable access to information");
            encryptedMsgOut = Utilities.CBCEncrypt(c.getToServer(), c.getSessionKey(), c.getInitVector());
            HMACTagOut = Utilities.genHMAC(c.getSessionKey(), c.getToServer()).toString();
            out.println(Base64.getEncoder().encodeToString(encryptedMsgOut));
            out.println(HMACTagOut);
            System.out.println("---------->");
            System.out.println("Client to Server: ");
            System.out.println("PlainText message: " + c.getToServer());
            System.out.println("Encrypted message: " + new String(encryptedMsgOut));
            System.out.println("HMAC tag: " + HMACTagOut);
            System.out.println("---------->");
            System.out.println();

            //*RECEIVE*
            encryptedMsgIn = Base64.getDecoder().decode(in.readLine());
            HMACTagIn = in.readLine();
            c.setFromServer(Utilities.CBCDecrypt(encryptedMsgIn, c.getSessionKey(), c.getInitVector()));
            System.out.println("<----------");
            System.out.println("Server to Client: ");
            System.out.println("Encrypted message: " + new String(encryptedMsgIn));
            //verify HMAC tag- close if false
            if(!Utilities.verifyHMAC(c.getSessionKey(), c.getFromServer(), new BigInteger(HMACTagIn))){
                System.out.println("System has detected a bad HMAC. Closing connection....");
                cSocket.close();
            }
            else{
                System.out.println("HMAC verified. Decrypting....");
            }
            System.out.println("Plaintext message: " + Utilities.CBCDecrypt(encryptedMsgIn, c.getSessionKey(), c.getInitVector()));
            System.out.println("<----------");
            System.out.println();
            System.out.println("Complete. Closing connection....");
            //Close connection
            in.close();
            out.close();
            cSocket.close();
        }
        catch(IOException ex){
            System.out.println("IOException in client main: " + ex.getMessage());
            ex.printStackTrace();
        }
        catch(Exception ex){
            System.out.println("Exception in client main: " + ex.getMessage());
            ex.printStackTrace();
        }
    }

}
