//File: Server.java
//Purpose: Server object class for SENG2250 assignment 3 - Task 2
//Programmer: Liam Craft - C3339847
//Date: 10/11/2020

import java.math.BigInteger;

public class Server {
    //****Class variables*****
    private String serverID;                //This server objects identifying code
    private String currentClientId;         //The client currently being communicated with
    private BigInteger serverP;             //A psuedo-random gen large prime for generating keys
    private BigInteger serverQ;             //A psuedo-random gen large prime for generating keys
    private BigInteger[][] serverKeys;      //The server's RSA key pair - 0(public key, n), 1(private key, n)
    private BigInteger serverPrivDHKey;     //The server's private Diffie-Hellman key
    private BigInteger serverPubDHKey;      //The server's public Diffie-Hellman key
    private BigInteger sessionKey;          //The current session key
    private BigInteger clientPubDHKey;      //The current client's public Diffie-Hellman key
    private byte[] initVector;              //A CBC initialisation vector - generated by the client.
    private String serverChallengeStr;      //A pre-agreed string for testing encryption
    private byte[] clientChallenge;         //String for testing encryption

    //****Server constructor****
    public Server(){
        this.serverID = "TEST_SERVER_0001";
        serverP = Utilities.getLargePrime();
        serverQ = Utilities.getLargePrime();
        serverKeys = Utilities.genRSAKeyPair(serverP, serverQ);
        serverPrivDHKey = Utilities.calcDHPrivKey();
        serverPubDHKey = Utilities.calcDHPubKey(serverPrivDHKey);
        this.serverChallengeStr = "c3339847c3339847c3339847c3339847c3339847c3339847c3339847c3339847";
    }

    //****Getters and setters****

    public String getServerID() {
        return serverID;
    }

    public String getCurrentClientId() {
        return currentClientId;
    }

    public void setCurrentClientId(String currentClientId) {
        this.currentClientId = currentClientId;
    }

    public BigInteger[][] getServerKeys() {
        return serverKeys;
    }

    public BigInteger getServerPrivDHKey() {
        return serverPrivDHKey;
    }

    public BigInteger getServerPubDHKey() {
        return serverPubDHKey;
    }

    public BigInteger getSessionKey() {
        return sessionKey;
    }

    public void setSessionKey(BigInteger sessionKey) {
        this.sessionKey = sessionKey;
    }

    public BigInteger getClientPubDHKey() {
        return clientPubDHKey;
    }

    public void setClientPubDHKey(BigInteger clientPubDHKey) {
        this.clientPubDHKey = clientPubDHKey;
    }

    public byte[] getInitVector() {
        return initVector;
    }

    public void setInitVector(byte[] initVector) {
        this.initVector = initVector;
    }

    public String getServerChallengeStr() {
        return serverChallengeStr;
    }

    public byte[] getClientChallenge() {
        return clientChallenge;
    }

    public void setClientChallenge(byte[] clientChallenge) {
        this.clientChallenge = clientChallenge;
    }

}
