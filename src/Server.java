//File: Server.java
//Purpose: Server object class for SENG2250 assignment 3 - Task 2
//Programmer: Liam Craft - C3339847
//Date: 10/11/2020

import java.math.BigInteger;
import java.io.*;
import java.net.*;
import java.util.Random;
import java.security.SecureRandom;

public class Server {
    private BigInteger serverP;
    private BigInteger serverQ;
    private BigInteger[][] serverKeys;      //0(public key, n), 1(private key, n)
    String input, output, initMessage;
    //Default constructor
    public Server(){
        serverP = Utilities.getLargePrime();
        serverQ = Utilities.getLargePrime();
        serverKeys = Utilities.genRSAKeyPair(serverQ, serverQ);
    }

    //Server constructor
    public Server(BigInteger p, BigInteger q){
        this.serverP = p;
        this.serverQ = q;
        serverKeys = Utilities.genRSAKeyPair(serverQ, serverQ);
    }

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
            System.out.println("TEST original init client: " + initMessage);
            //TEST
            System.out.println("Server initHash test output: " + initHash.toString());
            //generate sig with hashed message and servers PRIVATE key(in two parts for simplicity)
            BigInteger serverRSASig = Utilities.encodeRSA(initHash, serverKeys[1][0], serverKeys[1][1]);
            //TEST
            System.out.println("Server sig test output: " + serverRSASig.toString());
            out.println(serverRSASig);
            //TEST modPow in and out with both keys
            BigInteger test = Utilities.SHA256Hash(initMessage);


            //TODO: Close connection
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
