//File: ServerMain.java
//Purpose: Main class for Server SENG2250 assignment 3 - Task 2
//Programmer: Liam Craft - C3339847
//Date:10/11/2020

import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.util.Base64;

public class ServerMain {
    public static void main(String[] args){
       Server s = new Server();
       //s.run();
        System.out.println("Running");
        System.out.println("Waiting for client.....");
        String input, output, initMessage;
        BigInteger[][] serverKeys = s.getServerKeys();
        try {
            ServerSocket sSocket = new ServerSocket(6969);
            Socket sClientSocket = sSocket.accept();
            PrintWriter out = new PrintWriter(sClientSocket.getOutputStream(), true);
            BufferedReader in = new BufferedReader(new InputStreamReader(sClientSocket.getInputStream()));
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
            out.println(serverKeys[0][0].toString());
            //n value
            out.println(serverKeys[0][1].toString());
            //send RSA signature
            //hash the init message
            BigInteger initHash = Utilities.SHA256Hash(initMessage);
            //NOTE:Encrypt with public key, decrypt with private
            //generate sig with hashed message and servers private key(in two parts for simplicity)
            // (hashed hello msg, d, n)
            BigInteger serverRSASig = Utilities.encodeRSA(initHash, serverKeys[1][0], serverKeys[1][1]);
            out.println(serverRSASig);
            //****Handshake phase****
            //Receive and send id's
            s.setCurrentClientId(in.readLine());
            //send server id
            out.println(s.getServerID());
            //***DH key exchange***
            //receive client DH public key
            s.setClientPubDHKey(new BigInteger(in.readLine()));
//            //send server DH public key
            out.println(s.getServerPubDHKey());
            //calc DH session key
            s.setSessionKey(Utilities.calcDHSessionKey(s.getClientPubDHKey(), s.getServerPrivDHKey()));
            //receive IV from client
            s.setInitVector(Base64.getDecoder().decode(in.readLine()));
            //test encryption with challenge response
            //get challenge from client
            s.setClientChallenge(Base64.getDecoder().decode(in.readLine()));
            //send response to client
            out.println(Base64.getEncoder().encodeToString(Utilities.CBCEncrypt(s.getServerChallengeStr(), s.getSessionKey(), s.getInitVector())));
            //Do decryption test
            if(Utilities.sesKeyMsgCheck(Utilities.CBCDecrypt(s.getClientChallenge(), s.getSessionKey(), s.getInitVector()), s.getServerChallengeStr())){
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
            if(!Utilities.verifyHMAC(s.getSessionKey(), s.getCurrentClientId(), new BigInteger(HMACTagIn))){
                System.out.println("Server has detected a bad HMAC. Closing connection....");
                sSocket.close();
            }
            System.out.println("Decrypted msg: " + Utilities.CBCDecrypt(encryptedMsgIn, s.getSessionKey(), s.getInitVector()));

            //*SEND*
            //create msg
            output = "Integrity: Guarding against improper information modification***";
            encryptedMsgOut = Utilities.CBCEncrypt(output, s.getSessionKey(), s.getInitVector());
            HMACTagOut = Utilities.genHMAC(s.getSessionKey(), s.getServerID()).toString();
            out.println(Base64.getEncoder().encodeToString(encryptedMsgOut));
            out.println(HMACTagOut);

            //*RECEIVE*
            encryptedMsgIn = Base64.getDecoder().decode(in.readLine());
            HMACTagIn = in.readLine();
            //verify HMAC - close connection if false
            if(!Utilities.verifyHMAC(s.getSessionKey(), s.getCurrentClientId(), new BigInteger(HMACTagIn))){
                System.out.println("Server has detected a bad HMAC. Closing connection....");
                sSocket.close();
            }
            System.out.println("Decrypted msg: " + Utilities.CBCDecrypt(encryptedMsgIn, s.getSessionKey(), s.getInitVector()));

            //*SEND*
            output = "These three concepts are often referred to as the CIA triad*****";
            encryptedMsgOut = Utilities.CBCEncrypt(output, s.getSessionKey(), s.getInitVector());
            HMACTagOut = Utilities.genHMAC(s.getSessionKey(), s.getServerID()).toString();
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
}
