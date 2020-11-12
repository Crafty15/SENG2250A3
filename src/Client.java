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
    private BigInteger[] serverPublicKey;
    private String initMsg;
    private BigInteger serverRSASig;
    private BigInteger clientPubDHKey;
    private BigInteger clientPrivDHKey;
    private BigInteger sessionKey;
    private BigInteger serverPubDHKey;


    //Default constructor
    public Client(){
        serverPublicKey = new BigInteger[2];
        initMsg = "";
        clientPrivDHKey = Utilities.calcDHPrivKey();
        clientPubDHKey = Utilities.calcDHPubKey(clientPrivDHKey);
    }

    //Constructor
    public Client(BigInteger p, BigInteger g){
        serverPublicKey = new BigInteger[2];
        initMsg = "";
        clientPrivDHKey = Utilities.calcDHPrivKey();
        clientPubDHKey = Utilities.calcDHPubKey(clientPrivDHKey);
    }

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
            //pubkey
            serverPublicKey[0] = new BigInteger(in.readLine());
            //n
            serverPublicKey[1] = new BigInteger(in.readLine());
            //Client responds with it's ID
            System.out.println("Server to client: RSA_PK =  " + serverPublicKey[0]);
//            String test = in.readLine();
            serverRSASig = new BigInteger(in.readLine());
            //try to verify the servers signature
            if(this.verifyRSA(initMsg, serverRSASig)){
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
            //receive server DH public key
            this.serverPubDHKey = new BigInteger(in.readLine());
            //TEST - output for key exchange
            System.out.println("Client received server DH public key: " + this.serverPubDHKey);
            //********test send byte array***********


            byte[] test = new byte[10];
            Random rand = new SecureRandom();
            String encTest = Base64.getEncoder().encodeToString(test);
            rand.nextBytes(test);
            System.out.println("Byte array cust: "+encTest);

            out.println(encTest);
            //********test send byte array***********
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

    //verify RSA
    public boolean verifyRSA(String original, BigInteger RSAsig){
        //hash the clients version of the init message
        //TEST
//        System.out.println("TEST original init client: " + original);
        BigInteger hOriginal = Utilities.SHA256Hash(original);
        //TEST
//        System.out.println("TEST hashed original: " + hOriginal);
        //decode RSA - using the hashed original and the server public keys
        //TODO: decoded RSA does not equal hashed original
        //BigInteger decodedRSA = Utilities.decodeRSA(RSAsig, serverPublicKey[0], serverPublicKey[1]);
        BigInteger RSAComparison = Utilities.decodeRSA(hOriginal, serverPublicKey[0], serverPublicKey[1]);
        //TEST
//        System.out.println("TEST client generated RSA for comparison: " + RSAComparison);
        //compare the hash values
        if(RSAComparison.equals(RSAsig)){
            return true;
        }
        return false;
    }



}
