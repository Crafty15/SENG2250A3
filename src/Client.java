//File: Client.java
//Purpose: Client object class for SENG2250 assignment 3 - Task 2
//Programmer: Liam Craft - C3339847
//Date: 10/11/2020

import java.math.BigInteger;
import java.io.*;
import java.net.*;
//TEST
import java.util.Base64;
import java.util.Random;
import java.security.SecureRandom;
import java.util.Base64.Encoder;
import java.util.Base64.Decoder;

public class Client {
    private BigInteger[] serverRSAKey;
    private String initMsg;
    private BigInteger serverRSASig;
    private BigInteger clientPubDHKey;
    private BigInteger clientPrivDHKey;
    private BigInteger sessionKey;
    private BigInteger serverPubDHKey;
    private byte[] initVector;
    private String ceTestStr;


    //Default constructor
    public Client(){
        serverRSAKey = new BigInteger[2];
        initMsg = "";
        clientPrivDHKey = Utilities.calcDHPrivKey();
        clientPubDHKey = Utilities.calcDHPubKey(clientPrivDHKey);
        this.initVector = Utilities.genIV();
        this.ceTestStr = "c3339847c3339847";
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
            if(Utilities.verifyRSA(initMsg, serverRSASig, serverRSAKey[0], serverRSAKey[1])){
                //server verified
                System.out.println("Server verified");
            }
            else{
                //Server not verified- close?
                System.out.println("Server verification failed. Closing....");
                System.exit(1);
            }
            //Send DH public key to server
            out.println(this.clientPubDHKey);
            //TEST - output for DH key exchange
            System.out.println("Client sent server DH public key: \n" + this.clientPubDHKey);
//            //receive server DH public key
            this.serverPubDHKey = new BigInteger(in.readLine());
//            //TEST - output for DH key exchange
            System.out.println("Client received server DH public key: \n" + this.serverPubDHKey);
            //calc DH session key
            this.sessionKey = Utilities.calcDHSessionKey(this.serverPubDHKey, this.clientPrivDHKey);
            //send IV to server
            out.println(Base64.getEncoder().encodeToString(this.initVector));
            //test encryption with pre-agreed challenge response messages



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
