//File: Client.java
//Purpose: Client object class for SENG2250 assignment 3 - Task 2
//Programmer: Liam Craft - C3339847
//Date: 10/11/2020

import java.math.BigInteger;
import java.io.*;
import java.net.*;

public class Client {
    private BigInteger clientP;
    private BigInteger clientG;
    private BigInteger[] serverPublicKey;
    private String initMsg;
    private BigInteger serverRSASig;

    //Default constructor
    public Client(){
        clientP = new BigInteger("0");
        clientG = new BigInteger("0");
        serverPublicKey = new BigInteger[2];
        initMsg = "";
    }

    //Constructor
    public Client(BigInteger p, BigInteger g){
        this.clientP = p;
        this.clientG = g;
        serverPublicKey = new BigInteger[2];
        initMsg = "";
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
            //TEST
            System.out.println("Test init msg main: " + initMsg);
            System.out.println("RSA verify test: " + verifyRSA(initMsg, serverRSASig));

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
        System.out.println("TEST original init client: " + original);
        BigInteger hOriginal = Utilities.SHA256Hash(original);
        //TEST
        System.out.println("TEST hashed original: " + hOriginal);
        //decode RSA
        BigInteger decodedRSA = Utilities.decodeRSA(RSAsig, serverPublicKey[0], serverPublicKey[1]);
        //TEST
        System.out.println("TEST decoded RSA: " + decodedRSA);
        //compare the hash values
        if(hOriginal.equals(RSAsig)){
            return true;
        }
        return false;
    }



}
