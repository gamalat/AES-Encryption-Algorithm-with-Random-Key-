package com.company;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

public class AES {


    //    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
//keyGen.init(256); // for example
//    SecretKey secretKey = keyGen.generateKey();
    private static final String ALGO = "AES";
    private static byte[] KeyValue;

    public AES(String Key) throws NoSuchAlgorithmException {
        KeyValue = Key.getBytes();
    }

    public AES() throws NoSuchAlgorithmException {
    }


    public static String world(String user) {
        return "Hello world " + user;
    }


    public static String encrypt(String Data) {

        Key key = generateKey();
        byte[] encVal;
        String encryptedValue = null;
        try {
            Cipher c = Cipher.getInstance(ALGO);
            c.init(Cipher.ENCRYPT_MODE, key);
            encVal = c.doFinal(Data.getBytes());
            encryptedValue = new BASE64Encoder().encode(encVal);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return encryptedValue;
    }

    public static String decrypt(String encryptedData) {
        byte[] decordedValue;
        byte[] decValue;
        String decryptedValue = null;
        try {
            Key key = generateKey();
            Cipher c = Cipher.getInstance(ALGO);
            c.init(Cipher.DECRYPT_MODE, key);
            decordedValue = new BASE64Decoder().decodeBuffer(encryptedData);
            decValue = c.update(decordedValue);
            decryptedValue = new String(decValue);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return decryptedValue;
    }

    public static String decrypteLoginPassword(String Data) {
        String result = "";
        int ascii;
        byte[] vals = Data.getBytes();
        for (byte b : vals) {
            ascii = ((int) b) - 25;
            char ch = (char) ascii;
            result = result.concat(ch + "");
        }
        return result;
    }

    public static String encrypteLoginPassword(String Data) {
        String Result = "";
        int ascii;
        byte[] vals = Data.getBytes();
        for (byte b : vals) {
            ascii = ((int) b) + 25;
            char ch = (char) ascii;
            Result = Result.concat(ch + "");
        }
        return Result;
    }

    public static Key generateKey() {

//        String str = "gamalatSrourSS21";
//        KeyValue = str.getBytes();
//        Key key = new SecretKeySpec(KeyValue, ALGO);
        KeyGenerator keyGen = null;
        try {
            keyGen = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        SecureRandom random = new SecureRandom(); // cryptograph. secure random
        keyGen.init(random);
        SecretKey secretKey = keyGen.generateKey();
        System.out.println(secretKey);

        return secretKey;
    }


    public static void main(String[] args) {

        try {
            AES aes = new AES("");
            //  System.out.println(h.encrypteLoginPassword("gogo"));
            String encryptedData = aes.encrypt("Password");
            System.out.println("Encrypted of Password One is " + encryptedData);
            String pass = aes.encrypt("Password");
            System.out.println("Encrypted of Password TWO is " + pass);

            //  String decryptedData = h.decrypt("6vZegY3cCB8DBJTgzyfTew==");
            //  System.out.println("decrypted of " + decryptedData + " is " + decryptedData);

        } catch (Exception e) {
            Logger.getLogger(AES.class.getName()).log(Level.SEVERE, null, e);
        }
    }


}
