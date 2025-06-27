package ciphers;



import javax.crypto.spec.IvParameterSpec;

import prngs.SecureRandomWrapper;

public class AESCBCChiperWrapper extends CipherWrapper {

    private final byte[] ivBytes;
    private final IvParameterSpec ivSpec;

    public AESCBCChiperWrapper(SecureRandomWrapper srw) throws Exception {
        super("AES/CBC/PKCS5Padding", "AES", srw);
        this.ivBytes = srw.generateIV(); // 16-byte IV
        this.ivSpec = new IvParameterSpec(ivBytes);
    }
    
    public AESCBCChiperWrapper(SecureRandomWrapper srw, byte[] ivBytes ) throws Exception {
        super("AES/CBC/PKCS5Padding", "AES", srw);
        this.ivBytes = ivBytes; // 16-byte IV
        this.ivSpec = new IvParameterSpec(ivBytes);
    }

    public byte[] encrypt(String plaintext) throws Exception {
        return super.encrypt(plaintext, ivSpec);
    }

    public String decrypt(byte[] ciphertext) throws Exception {
        return super.decrypt(ciphertext, ivSpec);
    }

    public byte[] getIV() {
        return ivBytes;
    }
}
