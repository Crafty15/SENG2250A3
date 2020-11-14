//File: Server.java
//Purpose: Server object class for SENG2250 assignment 3 - Task 2
//Programmer: Liam Craft - C3339847
//Date: 10/11/2020

import java.math.BigInteger;
import java.io.*;
import java.net.*;
import java.util.Base64;

public class Server {
    private String serverID;
    private String currentClientId;
    private BigInteger serverP;
    private BigInteger serverQ;
    private BigInteger[][] serverKeys;      //0(public key, n), 1(private key, n)
    private BigInteger serverPrivDHKey;
    private BigInteger serverPubDHKey;
    private BigInteger sessionKey;
    private BigInteger clientPubDHKey;
    private byte[] initVector;
    private String serverChallengeStr;
    private byte[] clientChallenge;
    String input, output, initMessage;
    //Default constructor
    public Server(){
        this.serverID = "TEST_SERVER_0001";
        serverP = Utilities.getLargePrime();
        serverQ = Utilities.getLargePrime();
        serverKeys = Utilities.genRSAKeyPair(serverP, serverQ);
        serverPrivDHKey = Utilities.calcDHPrivKey();
        serverPubDHKey = Utilities.calcDHPubKey(serverPrivDHKey);
        this.serverChallengeStr = "c3339847c3339847c3339847c3339847c3339847c3339847c3339847c3339847";
    }

    //Server constructor
//    public Server(BigInteger p, BigInteger q){
//        this.serverP = p;
//        this.serverQ = q;
//        serverKeys = Utilities.genRSAKeyPair(serverP, serverQ);
//        serverPrivDHKey = Utilities.calcDHPrivKey();
//        serverPubDHKey = Utilities.calcDHPubKey(serverPrivDHKey);
//    }

    //Server run
    //TODO: Args to determine ports?
    public void run(){
        System.out.println("Running");
        System.out.println("Waiting for client.....");
        try {
            ServerSocket sSocket = new ServerSocket(6969);
            Socket sClientSocket = sSocket.accept();
            PrintWriter out = new PrintWriter(sClientSocket.getOutputStream(), true);
            BufferedReader in = new BufferedReader(new InputStreamReader(sClientSocket.getInputStream()));
            //input output message strings
//            String input, output;
            //wait for client message...
            input = in.readLine();
            //loop until init message received
            while(!input.equalsIgnoreCase("Hello")){
                out.println("I'm not initialising until you say hello...");
                input = in.readLine();
            }
            initMessage = input;
            out.println("Connection established");
            //send server public key - convert to byte array and loop to send
            //public key
            out.println(this.serverKeys[0][0].toString());
            //n value
            out.println(this.serverKeys[0][1].toString());
            //send RSA signature
            //hash the init message
            BigInteger initHash = Utilities.SHA256Hash(initMessage);
            //TEST
//            System.out.println("TEST original init client: " + initMessage);
            //TEST
//            System.out.println("Server initHash test output: " + initHash.toString());
            //NOTE:Encrypt with public key, decrypt with private
            //generate sig with hashed message and servers private key(in two parts for simplicity)
            // (hashed hello msg, d, n)
            BigInteger serverRSASig = Utilities.encodeRSA(initHash, serverKeys[1][0], serverKeys[1][1]);
            out.println(serverRSASig);
            //****Handshake phase****
            //Receive and send id's
            this.currentClientId = in.readLine();
            //send server id
            out.println(this.serverID);
            //***DH key exchange***
            //receive client DH public key
            this.clientPubDHKey = new BigInteger(in.readLine());
//            //TEST - output for key exchange
            //System.out.println("Server received client DH public key: \n" + this.clientPubDHKey);
//            //send server DH public key
            out.println(this.serverPubDHKey);
            //calc DH session key
            this.sessionKey = Utilities.calcDHSessionKey(this.clientPubDHKey, this.serverPrivDHKey);
            //receive IV from client
            this.initVector = Base64.getDecoder().decode(in.readLine());
            //test encryption with challenge response
            //get challenge from client
            this.clientChallenge = Base64.getDecoder().decode(in.readLine());
            //send response to client
            out.println(Base64.getEncoder().encodeToString(Utilities.CBCEncrypt(this.serverChallengeStr, this.sessionKey, this.initVector)));
            //Do decryption test
            //TEST
            //System.out.println("CBC decrypt server side test: " + Utilities.CBCDecrypt(this.clientChallenge, this.sessionKey, this.initVector));
            if(Utilities.sesKeyMsgCheck(Utilities.CBCDecrypt(this.clientChallenge, this.sessionKey, this.initVector), this.serverChallengeStr)){
                System.out.println("Client session key verified.");
            }
            else{
                System.out.println("Error: Client session key verification failed.");
                System.exit(1);
            }
            //****data exchange*****
            byte[] encryptedMsgOut, encryptedMsgIn;
            String HMACTagOut = "", HMACTagIn = "";
            BigInteger bigHMACTagIn;

            //*RECEIVE*
            encryptedMsgIn = Base64.getDecoder().decode(in.readLine());
            HMACTagIn = in.readLine();
            //verify HMAC - close connection if false
            if(!Utilities.verifyHMAC(this.sessionKey, this.currentClientId, new BigInteger(HMACTagIn))){
                System.out.println("Server has detected a bad HMAC. Closing connection....");
                sSocket.close();
            }
            System.out.println("Decrypted msg: " + Utilities.CBCDecrypt(encryptedMsgIn, this.sessionKey, this.initVector));

            //*SEND*
            //create msg
            output = "Integrity: Guarding against improper information modification***";
            encryptedMsgOut = Utilities.CBCEncrypt(output, this.sessionKey, this.initVector);
            HMACTagOut = Utilities.genHMAC(this.sessionKey, this.serverID).toString();
            out.println(Base64.getEncoder().encodeToString(encryptedMsgOut));
            out.println(HMACTagOut);

            //*RECEIVE*
            encryptedMsgIn = Base64.getDecoder().decode(in.readLine());
            HMACTagIn = in.readLine();
            //verify HMAC - close connection if false
            if(!Utilities.verifyHMAC(this.sessionKey, this.currentClientId, new BigInteger(HMACTagIn))){
                System.out.println("Server has detected a bad HMAC. Closing connection....");
                sSocket.close();
            }
            System.out.println("Decrypted msg: " + Utilities.CBCDecrypt(encryptedMsgIn, this.sessionKey, this.initVector));

            //*SEND*
            output = "These three concepts are often referred to as the CIA triad*****";
            encryptedMsgOut = Utilities.CBCEncrypt(output, this.sessionKey, this.initVector);
            HMACTagOut = Utilities.genHMAC(this.sessionKey, this.serverID).toString();
            out.println(Base64.getEncoder().encodeToString(encryptedMsgOut));
            out.println(HMACTagOut);
            //Close connection
            System.out.println("Complete. Closing connection....");
            in.close();
            out.close();
            sSocket.close();
        }
        catch(IOException ex){
            System.out.println("IOException in server main: " + ex.getMessage());
            ex.printStackTrace();
        }
        catch(Exception ex){
            System.out.println("Exception in server main: " + ex.getMessage());
            ex.printStackTrace();
        }
    }
    //Getters and setters
    public BigInteger getServerP() {
        return serverP;
    }

    public void setServerP(BigInteger serverP) {
        this.serverP = serverP;
    }

    public BigInteger getServerQ() {
        return serverQ;
    }

    public void setServerQ(BigInteger serverQ) {
        this.serverQ = serverQ;
    }

    //


}
