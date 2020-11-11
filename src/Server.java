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
    //Default constructor
    public Server(){
        serverP = Utilities.getLargePrime();
        serverQ = Utilities.getLargePrime();
    }

    //Server constructor
    public Server(BigInteger p, BigInteger q){
        this.serverP = p;
        this.serverQ = q;
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
            String input, output;
            //wait for client message...
            input = in.readLine();
            out.println("Connection established - ECHO: " + input);
            out.println("RSAPPublicKey TEST");
        }
        catch(IOException e){
            System.out.println("IOException in server main: " + e.getMessage());
        }
        catch(Exception e){
            System.out.println("Exception in server main: " + e.getMessage());
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
