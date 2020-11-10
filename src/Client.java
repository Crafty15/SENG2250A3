//File: Client.java
//Purpose: Client object class for SENG2250 assignment 3 - Task 2
//Programmer: Liam Craft - C3339847
//Date: 10/11/2020

import java.math.BigInteger;
import java.io.*;
import java.net.*;

public class Client {
    private BigInteger clientP;
    private BigInteger clientQ;

    //Client constructor
    public Client(BigInteger p, BigInteger q){
        this.clientP = p;
        this.clientQ = q;
    }

}
