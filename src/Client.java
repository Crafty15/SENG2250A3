//File: Client.java
//Purpose: Client object class for SENG2250 assignment 3 - Task 2
//Programmer: Liam Craft - C3339847
//Date: 10/11/2020

import java.math.BigInteger;
import java.io.*;
import java.net.*;
//TEST
import java.util.Base64;

public class Client {
    private String clientID;
    private String currentServerId;
    private BigInteger[] serverRSAKey;
    private String initMsg;
    private BigInteger serverRSASig;
    private BigInteger clientPubDHKey;
    private BigInteger clientPrivDHKey;
    private BigInteger sessionKey;
    private BigInteger serverPubDHKey;
    private byte[] initVector;
    private String clientChallengeStr;
    private byte[] challengeResponse;


    //Constructor
    public Client(){
        this.clientID = "TEST_CLIENT_1212";
        serverRSAKey = new BigInteger[2];
        initMsg = "";
        clientPrivDHKey = Utilities.calcDHPrivKey();
        clientPubDHKey = Utilities.calcDHPubKey(clientPrivDHKey);
        this.initVector = Utilities.genIV();
        this.clientChallengeStr = "c3339847c3339847c3339847c3339847c3339847c3339847c3339847c3339847";
        this.challengeResponse = null;
    }

    //run Client class
    public void run(){
        try{
            Socket cSocket = new Socket("localHost", 6969);
            PrintWriter out = new PrintWriter(cSocket.getOutputStream(), true);
            BufferedReader in = new BufferedReader(new InputStreamReader(cSocket.getInputStream()));
            //input/output message strings
            String fromServer, toServer;
            System.out.println("----------------");
            System.out.println("***Setup Phase***");
            System.out.println("-----------------");
            System.out.println("Waiting on input.....");
            //client to server - "Hello" will initiate the setup phase
            toServer = System.console().readLine();
            //send init msg to server
            out.println(toServer);
            System.out.println("---------->");
            System.out.println("Client to server: " + toServer);
            //get response from server - loop until proper init message "Hello" is sent. Just for giggles
            fromServer = in.readLine();
            while(!fromServer.equalsIgnoreCase("Connection established")){
                System.out.println(fromServer);
                System.out.println("Waiting on input.....");
                toServer = System.console().readLine();
                out.println(toServer);
                fromServer = in.readLine();
            }
            initMsg = toServer;
            System.out.println("---------->");
            System.out.println("<----------");
            System.out.println("Server response: " + fromServer);
            //fromServer = in.readLine();
            //server responds with it's RSA public key
            //pubkey - e
            serverRSAKey[0] = new BigInteger(in.readLine());
            //n
            serverRSAKey[1] = new BigInteger(in.readLine());
            //Client responds with it's ID
            System.out.println("Server to client: RSA_PK =  \n" + serverRSAKey[0] + " + " + serverRSAKey[1]);
            serverRSASig = new BigInteger(in.readLine());
            System.out.println("<----------");
            System.out.println();
            System.out.println("Client: Verifying RSA signature....");
            if(Utilities.verifyRSA(initMsg, serverRSASig, serverRSAKey[0], serverRSAKey[1])){
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
            out.println(this.clientID);
            //receive server id
            this.currentServerId = in.readLine();
            System.out.println("---------->");
            System.out.println("CLient to server:");
            System.out.println("Client ID: " + this.clientID);
            System.out.println("---------->");
            System.out.println();
            System.out.println("<----------");
            System.out.println("Server to client:");
            System.out.println("Server ID: " + this.currentServerId);
            System.out.println("<----------");
            System.out.println();

            //***DH key exchange***
            //Send DH public key to server
            out.println(this.clientPubDHKey);
            System.out.println("---------->");
            System.out.println("CLient to server:");
            System.out.println("DH public key: \n" + this.clientPubDHKey);
//            //receive server DH public key
            this.serverPubDHKey = new BigInteger(in.readLine());
            System.out.println("---------->");
            System.out.println();
            System.out.println("<----------");
            System.out.println("Server to client:");
            System.out.println("Received DH public key: \n" + this.serverPubDHKey);
            System.out.println("");
            System.out.println("<----------");
            //calc DH session key
            this.sessionKey = Utilities.calcDHSessionKey(this.serverPubDHKey, this.clientPrivDHKey);
            //send IV to server
            System.out.println("---------->");
            out.println(Base64.getEncoder().encodeToString(this.initVector));
            toServer = Base64.getEncoder().encodeToString(Utilities.CBCEncrypt(this.clientChallengeStr, this.sessionKey, this.initVector));
            out.println(toServer);
            System.out.println("Challenge sent to server");
            System.out.println("Agreed encrypted message?: " + toServer);
            System.out.println("---------->");
            //receive servers challenge response
            System.out.println();
            System.out.println("<----------");
            System.out.println("Server - Challenge response");
            this.challengeResponse = Base64.getDecoder().decode(in.readLine());
            System.out.println("Agreed encrypted message?: " + toServer);
            System.out.println("<----------");
            System.out.println();
            System.out.println("Checking server session key....");
            if(Utilities.sesKeyMsgCheck(Utilities.CBCDecrypt(this.challengeResponse, this.sessionKey, this.initVector), this.clientChallengeStr)){
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
            System.out.println();

            //client sends encrypted text to server (2 exchanges) - ensure each is 64 bytes
            //*SEND* (message and HMAC tag)
            //create messages
            toServer = "Confidentiality Preserving authorized restrictions on info******"; //64 bytes
            encryptedMsgOut = Utilities.CBCEncrypt(toServer, this.sessionKey, this.initVector);
            HMACTagOut = Utilities.genHMAC(this.sessionKey, this.clientID).toString();
            //send messages
            out.println(Base64.getEncoder().encodeToString(encryptedMsgOut));
            out.println(HMACTagOut);
//            System.out.println();
            System.out.println("---------->");
            System.out.println("Client to Server: ");
            System.out.println("PlainText message: " + toServer);
            System.out.println("Encrypted message: " + new String(encryptedMsgOut));
            System.out.println("HMAC tag: " + HMACTagOut);
            System.out.println("---------->");
            System.out.println();
            //*RECEIVE*
            encryptedMsgIn = Base64.getDecoder().decode(in.readLine());
            HMACTagIn = in.readLine();
            System.out.println("<----------");
            System.out.println("Server to Client: ");
            System.out.println("Encrypted message: " + new String(encryptedMsgIn));
            //verify HMAC tag- close if false
            if(!Utilities.verifyHMAC(this.sessionKey, this.currentServerId, new BigInteger(HMACTagIn))){
                System.out.println("System has detected a bad HMAC. Closing connection....");
                cSocket.close();
            }
            else{
                System.out.println("HMAC verified. Decrypting....");
            }
            System.out.println("Plaintext message: " + Utilities.CBCDecrypt(encryptedMsgIn, this.sessionKey, this.initVector));
            System.out.println("<----------");
            System.out.println();
            //*SEND*
            toServer = "Availability: Ensuring timely and reliable access to information";
            encryptedMsgOut = Utilities.CBCEncrypt(toServer, this.sessionKey, this.initVector);
            HMACTagOut = Utilities.genHMAC(this.sessionKey, this.clientID).toString();
            out.println(Base64.getEncoder().encodeToString(encryptedMsgOut));
            out.println(HMACTagOut);
            System.out.println("---------->");
            System.out.println("Client to Server: ");
            System.out.println("PlainText message: " + toServer);
            System.out.println("Encrypted message: " + new String(encryptedMsgOut));
            System.out.println("HMAC tag: " + HMACTagOut);
            System.out.println("---------->");
            System.out.println();

            //*RECEIVE*
            encryptedMsgIn = Base64.getDecoder().decode(in.readLine());
            HMACTagIn = in.readLine();
            System.out.println("<----------");
            System.out.println("Server to Client: ");
            System.out.println("Encrypted message: " + new String(encryptedMsgIn));
            //verify HMAC tag- close if false
            if(!Utilities.verifyHMAC(this.sessionKey, this.currentServerId, new BigInteger(HMACTagIn))){
                System.out.println("System has detected a bad HMAC. Closing connection....");
                cSocket.close();
            }
            else{
                System.out.println("HMAC verified. Decrypting....");
            }
            System.out.println("Plaintext message: " + Utilities.CBCDecrypt(encryptedMsgIn, this.sessionKey, this.initVector));
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
