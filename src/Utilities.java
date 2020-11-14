//File: Utilities.java
//Purpose: Utilities class for SENG2250 assignment 3 - Task 2
//Programmer: Liam Craft - C3339847
//Date: 10/11/2020


//import sun.security.mscapi.CKeyPairGenerator;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

public class Utilities {
    //****Class variables****
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

    //****Getters****
    public static BigInteger getDHp(){
        return DHp;
    }
    public static BigInteger getDHg(){
        return DHg;
    }

    //****Fast Modular Exponentiation
    public static BigInteger modPow(BigInteger base, BigInteger exponent, BigInteger modulus){
        BigInteger result = new BigInteger("1");
        if(modulus.equals(BigInteger.ONE)){
            return new BigInteger("0");
        }
        while(exponent.signum() == 1){
            if((exponent.and(BigInteger.ONE).equals(BigInteger.ONE))){
                result = (result.multiply(base)).mod(modulus);
            }
            exponent = exponent.shiftRight(1);
            base = (base.multiply(base)).mod(modulus);
        }
        return result;
    }

    //****RSA****
    // Generate an RSA key pair - Array index 0 = public, 1 = private.
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

    //Generate a psuedo random large prime generator
    public static BigInteger getLargePrime(){
        Random rand = new SecureRandom();
        return BigInteger.probablePrime(1024, rand);
    }

    //Encode a message - creating an RSA signature
    //input msg should be a hashed value - (hashed msg, d - priv key part, n - )
    public static BigInteger encodeRSA(BigInteger msg, BigInteger d, BigInteger n){
        BigInteger result = Utilities.modPow(msg, d, n);
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

    //Verify RSA signature
    public static boolean verifyRSA(String original, BigInteger RSAsig, BigInteger e, BigInteger n){
        //hash the clients version of the init message
        BigInteger hOriginal = Utilities.SHA256Hash(original);
        //decode RSA - using the hashed original and the server public keys
        BigInteger decodedRSA = Utilities.decodeRSA(RSAsig, e, n);
        //compare
        return hOriginal.equals(decodedRSA);
    }

    //Hash string using SHA256 algorithm
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
        return new BigInteger(hashed);
    }

    //calcDHPrivKey - loops while the generated prime is greater than the given primitive root
    public static BigInteger calcDHPrivKey(){
        BigInteger result = Utilities.getLargePrime();
        while(result.compareTo(Utilities.getDHp()) == 1){
            result = Utilities.getLargePrime();
        }
        return result;
    }

    //****Diffie-Hellman****
    //Calculate a public Diffie-Hellman key
    //public keys are calculated using the modpow function (shared value g, entities private key, shared p)
    public static BigInteger calcDHPubKey(BigInteger privKey){
        return Utilities.modPow(Utilities.getDHg(), privKey, Utilities.getDHp());
    }

    //Calculate a private Diffie-Hellman session key
    public static BigInteger calcDHSessionKey(BigInteger theirPubKey, BigInteger myPrivKey){
        return Utilities.modPow(theirPubKey, myPrivKey, Utilities.getDHp());
    }

    //Generate 16 bit initialisation vector
    public static byte[] genIV(){
        byte[] result = new byte[16];
        for(int i = 0; i < 16; i++){
            result[i] = (byte)(Math.random()*128);
        }
        return result;
    }

    //****CBC MODE****
    //Cypher block chain encryption - inputs will always be 16 byte multiples
    public static byte[] CBCEncrypt(String plainText, BigInteger key, byte[] iVec){
        byte[] cipherText = new byte[16];                     //holds the cipher text in between encryptions
        byte[] AESInput = new byte[16];                         //holds AES input
        byte[] cipherResultArr = new byte[64];      //The final result
        byte[][] ptBlocks = new byte[4][16];        //blocks of plain text
        byte[][] ctBlocks = new byte[4][16];        //blocks of ciphertext
        BigInteger hashedKey = Utilities.SHA256Hash(key.toString());
        //break plaintext into blocks of 16 bytes
        ptBlocks[0] = plainText.substring(0, 16).getBytes();
        ptBlocks[1] = plainText.substring(16, 32).getBytes();
        ptBlocks[2] = plainText.substring(32, 48).getBytes();
        ptBlocks[3] = plainText.substring(48, 64).getBytes();
        try{
            Cipher AES = Cipher.getInstance("AES/ECB/NoPadding");
            AES.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(hashedKey.toByteArray(), "AES"));

            //IV xor plaintext block 1
            for(int i = 0; i < ptBlocks[0].length; i++){
                AESInput[i] = (byte) (iVec[i] ^ ptBlocks[0][i]);
            }
            //AES encrypt step 1 - AES result into ciphertext arr
            cipherText = AES.doFinal(AESInput);
            //add the first result block to the result array
            for(int i = 0; i < cipherText.length; i++){
                ctBlocks[0][i] = cipherText[i];
            }

            //Ciphertext1 xor plaintext block 2
            for(int i = 0; i < ptBlocks[1].length; i++){
                AESInput[i] = (byte) (cipherText[i] ^ ptBlocks[1][i]);
            }
            //AES encrypt step 2 - AESInput into ciphertext arr
            cipherText = AES.doFinal(AESInput);
            //add the second result block to the result array
            for(int i = 0; i < cipherText.length; i++){
                ctBlocks[1][i] = cipherText[i];
            }

            //CipherText2 xor plaintext block 3
            for(int i = 0; i < ptBlocks[2].length; i++){
                AESInput[i] = (byte) (cipherText[i] ^ ptBlocks[2][i]);
            }
            //AES encrypt step 3 - AESInput into ciphertext arr
            cipherText = AES.doFinal(AESInput);
            //add the third result block to the result array
            for(int i = 0; i < cipherText.length; i++){
                ctBlocks[2][i] = cipherText[i];
            }

            //CipherText3 xor plaintext block 4
            for(int i = 0; i < ptBlocks[3].length; i++){
                AESInput[i] = (byte) (cipherText[i] ^ ptBlocks[3][i]);
            }
            //AES encrypt step 4 - AESInput into ciphertext arr
            cipherText = AES.doFinal(AESInput);
            //add the fourth result block to the result array
            for(int i = 0; i < cipherText.length; i++){
                ctBlocks[3][i] = cipherText[i];
            }

            //add to result array
            for(int i = 0; i < cipherResultArr.length; i++){
                if(i < 16){
                    cipherResultArr[i] = ctBlocks[0][i];
                }
                else if(i < 32){
                    cipherResultArr[i] = ctBlocks[1][i - 16];
                }
                else if(i < 48){
                    cipherResultArr[i] = ctBlocks[2][i - 32];
                }
                else{
                    cipherResultArr[i] = ctBlocks[3][i - 48];
                }
            }
        }
        catch(NoSuchAlgorithmException ex){
            System.out.println("NoSuchAlgorithmException in Utilities.CBCEncrypt: " + ex.getMessage());
            ex.printStackTrace();
        }
        catch(NoSuchPaddingException ex){
            System.out.println("NoSuchPaddingException in Utilities.CBCEncrypt: " + ex.getMessage());
            ex.printStackTrace();
        }
        catch(Exception ex){
            System.out.println("Exception in Utilities.CBCEncrypt: " + ex.getMessage());
            ex.printStackTrace();
        }
        return cipherResultArr;
    }

    //decrypt CBC
    public static String CBCDecrypt(byte[] cipherTextArr, BigInteger key, byte[] iVec){
        String result = "";
        byte[] cipherText = new byte[16];                     //holds the cipher text in between encryptions
        byte[] AESOutput = new byte[16];                         //holds AES input - reused between blocks
        byte[][] ctBlocks = new byte[4][16];                //blocks of cipher text
        byte[][] ptBlocks = new byte[4][16];                //Blocks of plain text
        BigInteger hashedKey = Utilities.SHA256Hash(key.toString());;
        //Split cipher text into blocks
        for(int i = 0; i < cipherTextArr.length; i++){
            if(i < 16){
                ctBlocks[0][i] = cipherTextArr[i];
            }
            else if(i < 32){
                ctBlocks[1][i - 16] = cipherTextArr[i];
            }
            else if(i < 48){
                ctBlocks[2][i - 32] = cipherTextArr[i];
            }
            else{
                ctBlocks[3][i - 48] = cipherTextArr[i];
            }
        }

        try{
            Cipher AES = Cipher.getInstance("AES/ECB/NoPadding");
            AES.init(Cipher.DECRYPT_MODE, new SecretKeySpec(hashedKey.toByteArray(), "AES"));
            //put ctBlock[0] through AES, then xor with iVec, will give plain text, put into AESOutput
            AESOutput = AES.doFinal(ctBlocks[0]);
            //xor with hashedKey - into ptBlocks[0] result is plaintext block 0 of final output
            for(int i = 0; i < AESOutput.length; i++){
                ptBlocks[0][i] = (byte)(iVec[i] ^ AESOutput[i]);
            }

            //put ctBlock[1] through AES, xor with previous ctBlock
            AESOutput = AES.doFinal(ctBlocks[1]);
            //xor with previous ctBlocks[0] - result is plain text 1 of final output
            for(int i = 0; i < AESOutput.length; i++){
                ptBlocks[1][i] = (byte)(ctBlocks[0][i] ^ AESOutput[i]);
            }

            //put ctBlock[2] through AES, then xor with ctBlock[1]
            AESOutput = AES.doFinal(ctBlocks[2]);
            //xor with previous ctBlocks[1] - result is plain text 2 of final output
            for(int i = 0; i < AESOutput.length; i++){
                ptBlocks[2][i] = (byte)(ctBlocks[1][i] ^ AESOutput[i]);
            }

            //put ctBLock[3] through AES, then xor with ctBlock[2]
            AESOutput = AES.doFinal(ctBlocks[3]);
            //xor with previous ctBlocks[2]
            for(int i = 0; i < AESOutput.length; i++){
                ptBlocks[3][i] = (byte)(ctBlocks[2][i] ^ AESOutput[i]);
            }

            //Put plaintext blocks into result string
            for(int i = 0; i < ptBlocks.length; i++){
                result += new String(ptBlocks[i]);
            }

        }
        catch(NoSuchAlgorithmException ex){
            System.out.println("NoSuchAlgorithmException in Utilities.CBCDecrypt: " + ex.getMessage());
            ex.printStackTrace();
        }
        catch(NoSuchPaddingException ex){
            System.out.println("NoSuchPaddingException in Utilities.CBCDecrypt: " + ex.getMessage());
            ex.printStackTrace();
        }
        catch(Exception ex){
            System.out.println("Exception in Utilities.CBCDecrypt: " + ex.getMessage());
            ex.printStackTrace();
        }
        return result;
    }

    //verify challenge response test message
    public static boolean sesKeyMsgCheck(String theirMessage, String myMessage){
        return theirMessage.equals(myMessage);
    }

    //genHMAC -
    //Generate a hashed message auth code/tag. Utilise the existing hashing method
    public static BigInteger genHMAC(BigInteger key, String msg){
        BigInteger hmac = null;
        BigInteger k = SHA256Hash(key.toString());
        //paddings - 64 bytes
        String opad = Utilities.strRepeat("5c", 32);
        String ipad = Utilities.strRepeat("36", 32);
        BigInteger xor1 = k.xor(new BigInteger(ipad,16));
        BigInteger xor2 = k.xor(new BigInteger(opad, 16));
        //hash (xor1 || msg)
        BigInteger xor1MsgH = SHA256Hash(xor1.toString() + msg);
        //hash xor2
        BigInteger xor2H = SHA256Hash(xor2.toString());
        //hash both previous and return
        hmac = SHA256Hash(xor2H.toString() + xor1MsgH.toString());
        return hmac;
    }

    //Check that a received hmac tag matches a generated tag
    public static boolean verifyHMAC(BigInteger key, String msg, BigInteger tag){
        return tag.equals(genHMAC(key, msg));
    }

    //Repeat the given string the given number of times
    public static String strRepeat(String toRepeat, int numRepeats){
        String result = "";
        for(int i = 0; i < numRepeats; i++){
            result += toRepeat;
        }
        return result;
    }

}
