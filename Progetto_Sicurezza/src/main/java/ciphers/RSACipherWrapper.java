package ciphers;

import java.security.*;
import javax.crypto.Cipher;

public class RSACipherWrapper {

    private final KeyPair keyPair;
    private final Cipher cipher;

    public RSACipherWrapper(int keySize) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(keySize);
        this.keyPair = keyGen.generateKeyPair();
        this.cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); // comune
    }

    public byte[] encrypt(String plaintext) throws Exception {
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        return cipher.doFinal(plaintext.getBytes());
    }

    public String decrypt(byte[] ciphertext) throws Exception {
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] decrypted = cipher.doFinal(ciphertext);
        return new String(decrypted);
    }

    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }

    public PrivateKey getPrivateKey() {
        return keyPair.getPrivate();
    }
    
}
