//File: Utilities.java
//Purpose: Utilities class for SENG2250 assignment 3 - Task 2
//Programmer: Liam Craft - C3339847
//Date: 10/11/2020


//import sun.security.mscapi.CKeyPairGenerator;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;
//import java.nio.charset.StandardCharsets;

public class Utilities {
    //Diffie-Hellman key exchange params
    //DHp - agreed large prime
    private static BigInteger DHp = new BigInteger("17801190547854226652823756245015999014523215636912067427327445031444" +
            "28657887370207706126952521234630795671567847784664499706507709207278" +
            "57050009668388144034129745221171818506047231150039301079959358067395" +
            "34871706631980226201971496652413506094591370759495651467285569060679" +
            "4135837542707371727429551343320695239");
    //DHg - primitive root
    private static BigInteger DHg = new BigInteger("17406820753240209518581198012352343653860449079456135097849583104059" +
            "99534884558231478515974089409507253077970949157594923683005742524387" +
            "61037084473467180148876118103083043754985190983472601550494691329488" +
            "08339549231385000036164648264460849230407872181895999905649609776936" +
            "8017749273708962006689187956744210730");

    //getters
    public static BigInteger getDHp(){
        return DHp;
    }
    public static BigInteger getDHg(){
        return DHg;
    }

    //modPow - TODO: Add a description
    public static BigInteger modPow(BigInteger base, BigInteger exponent, BigInteger modulus){
        //TEST
//        System.out.println("***modpow test : entered***");
//        System.out.println("modpow base: "+base);
//        System.out.println("modpow exponent: "+exponent);
//        System.out.println("modpow modulus: "+modulus);
//        System.out.println("**************************");
        BigInteger result = new BigInteger("1");
        if(modulus.equals(BigInteger.ONE)){
            //TEST
            System.out.println("modpow test modulus = ONE");
            return new BigInteger("0");
        }
        //NOTE: signum returns 1 if the bigint is positive
        //TEST
        //System.out.println("test modpow signum: " + exponent.signum());
        while(exponent.signum() == 1){
            //TEST
            //System.out.println("****test modpow result (inside loop)****: " + result);
            if((exponent.and(BigInteger.ONE).equals(BigInteger.ONE))){
                result = (result.multiply(base)).mod(modulus);
                //TEST
                //System.out.println("****test modpow result (inside if inside loop)****: " + result);
            }
            exponent = exponent.shiftRight(1);
            base = (base.multiply(base)).mod(modulus);
        }
        //TEST
//        System.out.println("**************************");
        //System.out.println("test modpow result: " + result);
//        System.out.println("**************************");
        return result;
    }

    //RSA - Array index 0 = public, 1 = private.
    public static BigInteger[][] genRSAKeyPair(BigInteger p, BigInteger g){
        BigInteger result[][] = new BigInteger[2][2];        //result public-private key pair - index 0 = public, 1 = private
        BigInteger e = new BigInteger("65537");     //Public key given in specs
        //n = product of p and q () || m = totient = (p - ONE)(q - ONE)
        //e = public key || d = private key
        //compute n
        BigInteger n = p.multiply(g);       //n is used as the modulus for both public and private keys
        //compute phi(totient)
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(g.subtract(BigInteger.ONE));
        //Here you would normally pick e, which should be: positive, smaller than totient and NOT be a factor of totient
        //NOTE: fixed public key is given in specs = 65537. No need to calc
        //Select a private key - d
        BigInteger d = e.modInverse(phi);
        //assign to result set  0 = (e, n), 1 =  (d, n)
        //Public parts
        result[0][0] = e;
        result[0][1] = n;
        //Private parts...lol
        result[1][0] = d;
        result[1][1] = n;
        return result;
    }


    //large prime gen
    //generate large prime
    public static BigInteger getLargePrime(){
        Random rand = new SecureRandom();
        return BigInteger.probablePrime(1024, rand);
    }

    //Generate RSA signature
    //input msg should be a hashed value - (hashed msg, d - priv key part, n - )
    public static BigInteger encodeRSA(BigInteger msg, BigInteger d, BigInteger n){
        //System.out.println("TEST hashed msg: " + msg.toString());
        BigInteger result = Utilities.modPow(msg, d, n);
//        System.out.println("TEST encode result: " + result);
        return result;
    }

    //Decode RSA signature
    //take the RSA signature, run through modpow along with the server public key parts e, n
    public static BigInteger decodeRSA(BigInteger msg, BigInteger e, BigInteger n){
        //convert input to bigint
        //BigInteger biMsg = new BigInteger(msg);
        //decode using private keys in the modpow method
        BigInteger result = Utilities.modPow(msg, e, n);
        return result;
    }

    //verify RSA
    public static boolean verifyRSA(String original, BigInteger RSAsig, BigInteger e, BigInteger n){
        //hash the clients version of the init message
        //TEST
//        System.out.println("TEST original init client: " + original);
        BigInteger hOriginal = Utilities.SHA256Hash(original);
        //TEST
//        System.out.println("TEST hashed original: " + hOriginal);
        //decode RSA - using the hashed original and the server public keys
        //TODO: decoded RSA does not equal hashed original
        BigInteger decodedRSA = Utilities.decodeRSA(RSAsig, e, n);
        //Decode the server's provided signature and compare it to the hashed original
//        BigInteger RSAComparison = Utilities.decodeRSA(hOriginal, keyPart1, keyPart2);
        //TEST
//        System.out.println("TEST client decoded RSA for comparison: " + decodedRSA);
        //compare the hash values
        return hOriginal.equals(decodedRSA);
    }

    //hash stuff SHA256
    public static BigInteger SHA256Hash(String input){
        MessageDigest sha256 = null;
        try{
            sha256 = MessageDigest.getInstance("SHA-256");
        }
        catch(NoSuchAlgorithmException e){
            System.out.println("Exception in Utilities.SHA256Hash: " + e.getMessage());
            e.printStackTrace();
        }
        byte[] hashed = sha256.digest(input.getBytes(StandardCharsets.UTF_8));
        //TEST hased output size - 32 * 8 = 256 bits
        System.out.println("hashed byte array length: "+hashed.length);
        return new BigInteger(hashed);
    }

    //calcDHPrivKey - loops while the generated prime is greater than the given primitive root
    public static BigInteger calcDHPrivKey(){
        BigInteger result = Utilities.getLargePrime();
        while(result.compareTo(Utilities.getDHp()) == 1){
            result = Utilities.getLargePrime();
        }
        //TEST result is less than DHp
        System.out.println("calcDHPrivKey result less than prim root, compareTo = " + result.compareTo(Utilities.getDHp()));
        return result;
    }

    //calcDHPubKey
    //NOTE: modpow(base, exponent, modulus)
    //public keys are calculated using the modpow function (shared value g, entities private key, shared p)
    public static BigInteger calcDHPubKey(BigInteger privKey){
        return Utilities.modPow(Utilities.getDHg(), privKey, Utilities.getDHp());
    }

    //calc diffie-hellman session key
    public static BigInteger calcDHSessionKey(BigInteger theirPubKey, BigInteger myPrivKey){
        return Utilities.modPow(theirPubKey, myPrivKey, Utilities.getDHp());
    }

    //generate 16 bit initialisation vector
    public static byte[] genIV(){
        byte[] result = new byte[16];
        for(int i = 0; i < 16; i++){
            result[i] = (byte)(Math.random()*128);
        }
        return result;
    }

    //Cypher block chain encryption - inputs will always be 16 byte multiples
    public static byte[] CBCEncrypt(String plainText, BigInteger key, byte[] iVec){
        String cipherText = "";
        byte[] cipherResultArr = new byte[64];
    }

    //genHMAC -
    // Generate a hashed message auth code. Utilise the existing hashing method
//    public static BigInteger genHMAC(BigInteger key, BigInteger msg){
//        return
//    }
//    //verify RSA
//    public static boolean verifyRSA(String original, BigInteger RSAsig){
//        //hash the clients version of the init message
//        BigInteger hOriginal = Utilities.SHA256Hash(original);
//        //decode RSA
//        BigInteger decodedRSA = Utilities.decodeRSA(RSAsig, );
//        if(hOriginal.equals(RSAsig)){
//            return true;
//        }
//        return false;
//    }
}
