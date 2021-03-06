//File: Client.java
//Purpose: Client object class for SENG2250 assignment 3 - Task 2
//Programmer: Liam Craft - C3339847
//Date: 10/11/2020

import java.math.BigInteger;

public class Client {
    //****Class variables*****
    private String clientID;                //This client object's identifying code
    private String currentServerId;         //The server that is currently being communicated with
    private BigInteger[] serverRSAKey;      //An RSA key received from the current server
    private String initMsg;                 //Initialising message
    private BigInteger serverRSASig;        //RSA signature from the current server
    private BigInteger clientPubDHKey;      //This Client object's public Diffie-Hellman key
    private BigInteger clientPrivDHKey;     //This Client object's private Diffie-Hellman key
    private BigInteger sessionKey;          //Decryption key shared with the current server
    private BigInteger serverPubDHKey;      //The current server's public Diffie-Hellman key
    private byte[] initVector;              //A CBC initialisation vector - generated by the client on object instantiation and sent to the server.
    private String clientChallengeStr;      //A pre-agreed string for testing encryption
    private byte[] challengeResponse;       //Current server's response to the encryption challenge
    String fromServer, toServer;            //Miscellaneous string variables for communication.


    //****Constructor****
    public Client(){
        this.clientID = "TEST_CLIENT_1212";
        serverRSAKey = new BigInteger[2];
        initMsg = "";
        clientPrivDHKey = Utilities.calcDHPrivKey();
        clientPubDHKey = Utilities.calcDHPubKey(clientPrivDHKey);
        this.initVector = Utilities.genIV();
        this.clientChallengeStr = "c3339847c3339847c3339847c3339847c3339847c3339847c3339847c3339847";
        this.challengeResponse = null;
    }

    //****Getters and setters****

    public String getClientID() {
        return clientID;
    }

    public String getFromServer() {
        return fromServer;
    }

    public void setFromServer(String fromServer) {
        this.fromServer = fromServer;
    }

    public String getToServer() {
        return toServer;
    }

    public void setToServer(String toServer) {
        this.toServer = toServer;
    }

    public String getCurrentServerId() {
        return currentServerId;
    }

    public void setCurrentServerId(String currentServerId) {
        this.currentServerId = currentServerId;
    }

    public BigInteger[] getServerRSAKey() {
        return serverRSAKey;
    }

    public String getInitMsg() {
        return initMsg;
    }

    public void setInitMsg(String initMsg) {
        this.initMsg = initMsg;
    }

    public BigInteger getServerRSASig() {
        return serverRSASig;
    }

    public BigInteger getClientPubDHKey() {
        return clientPubDHKey;
    }

    public BigInteger getClientPrivDHKey() {
        return clientPrivDHKey;
    }

    public BigInteger getSessionKey() {
        return sessionKey;
    }

    public void setSessionKey(BigInteger sessionKey) {
        this.sessionKey = sessionKey;
    }

    public BigInteger getServerPubDHKey() {
        return serverPubDHKey;
    }

    public void setServerPubDHKey(BigInteger serverPubDHKey) {
        this.serverPubDHKey = serverPubDHKey;
    }

    public byte[] getInitVector() {
        return initVector;
    }

    public String getClientChallengeStr() {
        return clientChallengeStr;
    }

    public byte[] getChallengeResponse() {
        return challengeResponse;
    }

    public void setChallengeResponse(byte[] challengeResponse) {
        this.challengeResponse = challengeResponse;
    }

}
