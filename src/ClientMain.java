//File: ClientMain.java
//Purpose: Main class for Client SENG2250 assignment 3 - Task 2
//Programmer: Liam Craft - C3339847
//Date:10/11/2020

import java.math.BigInteger;
import java.io.*;
import java.net.*;

public class ClientMain {
    public static void main(String[] args) {
        //TODO: have input args determine ports?
        Client c = new Client();
        c.run();


	// Sample output format
//        //****Setup****
//
//        System.out.println("Setup Phase");
//        System.out.println("-----------");
//        //client to server - "Hello" will initiate the setup phase
//        System.out.println("Client to server: " + "INSERT INIT MESSAGE HERE");
//        //server responds with it's RSA public key
//        System.out.println("Server to client: RSA_PK=" + "INSERT RSA_PK HERE");

        //****Handshake phase****
//        System.out.println("Handshake Phase");
//        System.out.println("----------------");
//        //Client responds with it's client ID - Random char/number string of choice
//        System.out.println("Client to server: IDc = " + "INSERT CLIENT ID HERE");
//        //Server responds with it's server ID - Random char/number string of choice
//        System.out.println("Server to client: IDc = " + "INSERT SERVER ID HERE");
//
//        //****Diffie-Hellman key exchange (for deciphering messages or something)
//        System.out.println("Server to client: DHp = " + "INSERT CLIENT DH KEY HERE (OR MAYBE NOT?)");
//        System.out.println("Client to server: DHg = " + "INSERT SERVER DH KEY HERE (POSSIBLY?)");
//
//        //****Data exchange****
//        //client sends encrypted text to server
//        System.out.println("Client to server: " + "INSERT CIPHERTEXT MESSAGE HERE");
//        //server responds with encrypted message
//        System.out.println("Server to client: " + "INSERT CIPHERTEXT RESPONSE HERE");

        //*********TEST STUFF*********
//        System.out.println("******TEST SHIT******");
//        System.out.println("Test modPow");
//        System.out.println(Utilities.modPow(new BigInteger("3785"), new BigInteger("8395"), new BigInteger("65537")));



    }
}
