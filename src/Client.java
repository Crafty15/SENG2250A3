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

    //Default constructor
    public Client(){

    }

    //Constructor
    public Client(BigInteger p, BigInteger g){
        this.clientP = p;
        this.clientG = g;
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
            //get response from server
            fromServer = in.readLine();
            System.out.println("Server response: " + fromServer);
            fromServer = in.readLine();
            //server responds with it's RSA public key
            System.out.println("Server to client: " + Utilities.getLargePrime());

        }
        catch(IOException e){
            System.out.println("IOException in client main: " + e.getMessage());
        }
        catch(Exception e){
            System.out.println("Exception in client main: " + e.getMessage());
        }
    }

}
