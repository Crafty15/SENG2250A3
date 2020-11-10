//File: Server.java
//Purpose: Server object class for SENG2250 assignment 3 - Task 2
//Programmer: Liam Craft - C3339847
//Date: 10/11/2020

import java.math.BigInteger;
import java.io.*;
import java.net.*;

public class Server {
    private BigInteger serverP;
    private BigInteger serverQ;

    //Server constructor
    public Server(BigInteger p, BigInteger q){
        this.serverP = p;
        this.serverQ = q;
    }

}
