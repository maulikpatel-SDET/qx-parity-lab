// Cross-language parity: 14 operations (P1-P14), Java JCA.
package com.qx.parity;

import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class AllOps {
    public static void run() throws Exception {
        byte[] msg = "parity".getBytes();
        SecureRandom rnd = new SecureRandom();

        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA"); rsa.initialize(2048);     // P1
        var rsaKp = rsa.generateKeyPair();
        Signature p2 = Signature.getInstance("SHA256withRSA"); p2.initSign(rsaKp.getPrivate()); p2.update(msg); p2.sign();  // P2
        Cipher p3 = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");               // P3
        p3.init(Cipher.ENCRYPT_MODE, rsaKp.getPublic()); p3.doFinal(msg);
        KeyPairGenerator ec = KeyPairGenerator.getInstance("EC"); ec.initialize(new ECGenParameterSpec("secp256r1")); // P4
        var ecKp = ec.generateKeyPair();
        Signature p4 = Signature.getInstance("SHA256withECDSA"); p4.initSign(ecKp.getPrivate()); p4.update(msg); p4.sign();
        KeyPairGenerator ed = KeyPairGenerator.getInstance("Ed25519");                         // P5
        Signature p5 = Signature.getInstance("Ed25519"); p5.initSign(ed.generateKeyPair().getPrivate()); p5.update(msg); p5.sign();
        Cipher p6 = Cipher.getInstance("AES/GCM/NoPadding");                                   // P6 SAFE
        Cipher p7 = Cipher.getInstance("AES/ECB/PKCS5Padding");                                // P7 WEAK
        Cipher p8 = Cipher.getInstance("DESede/CBC/PKCS5Padding");                             // P8
        Cipher p9 = Cipher.getInstance("ChaCha20-Poly1305");                                   // P9 SAFE
        MessageDigest p10 = MessageDigest.getInstance("MD5");                                  // P10
        MessageDigest p11 = MessageDigest.getInstance("SHA-1");                                // P11
        Mac p12 = Mac.getInstance("HmacSHA1"); p12.init(new SecretKeySpec("test-only".getBytes(), "HmacSHA1")); // P12
        SecretKeyFactory p13 = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");             // P13
        p13.generateSecret(new PBEKeySpec("pw".toCharArray(), "salt".getBytes(), 1000, 256));
        KeyAgreement p14 = KeyAgreement.getInstance("DH");                                     // P14
        SecretKey aes = KeyGenerator.getInstance("AES").generateKey();
        System.out.println(p6 + "" + p7 + p8 + p9 + p10 + p11 + p12 + p13 + p14 + aes + new IvParameterSpec(new byte[16]) + rnd);
    }
}
