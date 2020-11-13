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


    //Default constructor
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

    //Constructor
//    public Client(BigInteger p, BigInteger g){
//        serverRSAKey = new BigInteger[2];
//        initMsg = "";
//        clientPrivDHKey = Utilities.calcDHPrivKey();
//        clientPubDHKey = Utilities.calcDHPubKey(clientPrivDHKey);
//    }

    //run Client
    public void run(){
        //TODO: Args to determine ports?
        try{
            Socket cSocket = new Socket("localHost", 6969);
            PrintWriter out = new PrintWriter(cSocket.getOutputStream(), true);
            BufferedReader in = new BufferedReader(new InputStreamReader(cSocket.getInputStream()));
            //input/output message strings
            String fromServer, toServer;
            System.out.println("Setup Phase");
            System.out.println("-----------");
            System.out.println("Waiting on input.....");
            //client to server - "Hello" will initiate the setup phase
            toServer = System.console().readLine();
            //send init msg to server
            out.println(toServer);
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
            System.out.println("Server response: " + fromServer);
            //fromServer = in.readLine();
            //server responds with it's RSA public key
            //pubkey - e
            serverRSAKey[0] = new BigInteger(in.readLine());
            //n
            serverRSAKey[1] = new BigInteger(in.readLine());
            //Client responds with it's ID
            System.out.println("Server to client: RSA_PK =  \n" + serverRSAKey[0] + " + " + serverRSAKey[1]);
//            String test = in.readLine();
            serverRSASig = new BigInteger(in.readLine());
            //TEST
            //System.out.println("Test server received RSA sig: " + serverRSASig.toString());
            //try to verify the servers signature (original msg, received RSA sig, e, n)
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
            //****Handshake phase****
            System.out.println("Handshake Phase");
            System.out.println("----------------");
            //TODO: Send and receive id's
            //send client id
            out.println(this.clientID);
            //receive server id
            this.currentServerId = in.readLine();
            System.out.println("CLient to server:");
            System.out.println("Client ID: " + this.clientID);
            System.out.println("Server to client:");
            System.out.println("Server ID: " + this.currentServerId);

            //***DH key exchange***
            //Send DH public key to server
            out.println(this.clientPubDHKey);
            //TEST - output for DH key exchange
            System.out.println("Client sent DH public key to server: \n" + this.clientPubDHKey);
//            //receive server DH public key
            this.serverPubDHKey = new BigInteger(in.readLine());
//            //TEST - output for DH key exchange
            System.out.println("Client received server DH public key: \n" + this.serverPubDHKey);
            //calc DH session key
            this.sessionKey = Utilities.calcDHSessionKey(this.serverPubDHKey, this.clientPrivDHKey);
            //TEST
            //System.out.println("Client session key = " + this.sessionKey.toString());
            //send IV to server
            out.println(Base64.getEncoder().encodeToString(this.initVector));
            //test encryption with pre-agreed challenge response messages
            //Send encrypted challenge string to server to test encryption
            out.println(Base64.getEncoder().encodeToString(Utilities.CBCEncrypt(this.clientChallengeStr, this.sessionKey, this.initVector)));
            System.out.println("Challenge sent to server");
            //receive servers challenge response
            this.challengeResponse = Base64.getDecoder().decode(in.readLine());
            //Do decryption test
            //TEST
            //System.out.println("CBC decrypt client side test: " + Utilities.CBCDecrypt(this.challengeResponse, this.sessionKey, this.initVector));
            if(Utilities.sesKeyMsgCheck(Utilities.CBCDecrypt(this.challengeResponse, this.sessionKey, this.initVector), this.clientChallengeStr)){
                System.out.println("Server session key verified.");
            }
            else{
                System.out.println("Error: Server session key verification failed.");
                System.exit(1);
            }
            //data exchange
            byte[] encryptedMsgOut, encryptedMsgIn;
            String HMACTagOut = "", HMACTagIn = "";

            System.out.println("****Data exchange****");
            System.out.println("----------------");
            //client sends encrypted text to server (2 exchanges) - ensure each is 64 bytes
            //SEND (message and HMAC tag)
            //create messages
            toServer = "In cryptography an HMAC is a specific type of message auth code."; //64 bytes
            encryptedMsgOut = Utilities.CBCEncrypt(toServer, this.sessionKey, this.initVector);
            HMACTagOut = Utilities.genHMAC(this.sessionKey, this.clientID).toString();
            //send messages
            out.println(Base64.getEncoder().encodeToString(encryptedMsgOut));
            out.println(HMACTagOut);
            //RECEIVE
            
            //SEND

            //RECEIVE
            //TODO: Close connection
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
