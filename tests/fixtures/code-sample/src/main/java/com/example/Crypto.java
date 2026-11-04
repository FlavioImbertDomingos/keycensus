package com.example;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class Crypto {
    static byte[] sha1(byte[] in) throws Exception {
        return MessageDigest.getInstance("SHA-1").digest(in);
    }

    static Cipher legacy() throws Exception {
        return Cipher.getInstance("AES"); // AES/ECB/PKCS5Padding in SunJCE
    }

    static Cipher modern() throws Exception {
        return Cipher.getInstance("AES/GCM/NoPadding");
    }

    static KeyPair rsa() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(1024);
        return g.generateKeyPair();
    }

    static KeyPair ec() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        return g.generateKeyPair();
    }

    static Signature sig() throws Exception {
        return Signature.getInstance("SHA1withRSA");
    }

    static KeyAgreement agree() throws Exception {
        return KeyAgreement.getInstance("ECDH");
    }

    static SecretKey tdes() throws Exception {
        KeyGenerator k = KeyGenerator.getInstance("DESede");
        return k.generateKey();
    }
}
