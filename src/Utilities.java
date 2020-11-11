//File: Utilities.java
//Purpose: Utilities class for SENG2250 assignment 3 - Task 2
//Programmer: Liam Craft - C3339847
//Date: 10/11/2020

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

public class Utilities {
    //Diffie-Hellman key exchange params
    private BigInteger p = new BigInteger("17801190547854226652823756245015999014523215636912067427327445031444" +
            "28657887370207706126952521234630795671567847784664499706507709207278" +
            "57050009668388144034129745221171818506047231150039301079959358067395" +
            "34871706631980226201971496652413506094591370759495651467285569060679" +
            "4135837542707371727429551343320695239");
    private BigInteger g = new BigInteger("17406820753240209518581198012352343653860449079456135097849583104059" +
            "99534884558231478515974089409507253077970949157594923683005742524387" +
            "61037084473467180148876118103083043754985190983472601550494691329488" +
            "08339549231385000036164648264460849230407872181895999905649609776936" +
            "8017749273708962006689187956744210730");

    //modPow - TODO: ADD SOMETHING HERE
    public static BigInteger modPow(BigInteger base, BigInteger exponent, BigInteger modulus){
        //BigInteger bOne = new BigInteger("1");
        //BigInteger bZero = new BigInteger("0");
        BigInteger result = new BigInteger("1");
        if(modulus.equals(BigInteger.ONE)){
            return new BigInteger("0");
        }
        //NOTE: signum returns 1 if the bigint is positive
        while(exponent.signum() == 1){
            if((exponent.and(BigInteger.ZERO).equals(BigInteger.ONE))){
                result = (result.multiply(base)).mod(modulus);
            }
            exponent = exponent.shiftRight(1);
            base = (base.multiply(base)).mod(modulus);
        }
        return result;
    }

    //RSA -
    //NOTE: Large prime should be provided by the server whenever needed
    public String genRSAPublicKey(BigInteger p, BigInteger q){
        //n = product of p and q | m = totient = (p - ONE)(q - ONE)
        //e = 
        BigInteger n = p.multiply(q);
        BigInteger totient
    }

    //large prime gen
    //generate large prime
    public static BigInteger getLargePrime(){
        Random rand = new SecureRandom();
        return BigInteger.probablePrime(2048/2, rand);
    }

}
