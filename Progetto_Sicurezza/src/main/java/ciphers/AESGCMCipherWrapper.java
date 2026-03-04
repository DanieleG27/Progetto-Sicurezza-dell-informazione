package ciphers;

import javax.crypto.spec.GCMParameterSpec;

import prngs.SecureRandomWrapper;

public class AESGCMCipherWrapper extends CipherWrapper{

    private final int MAC_LENGTH = 128;

    public AESGCMCipherWrapper(SecureRandomWrapper srw) throws Exception {
    	super("AES/GCM/NoPadding", "AES", srw);


    }

    public byte[] encrypt(String plaintext, String additionalData, byte[] iv) throws Exception {
    	GCMParameterSpec gcmSpec = new GCMParameterSpec(MAC_LENGTH, iv);
    	return super.encrypt(plaintext, additionalData, gcmSpec);
    }
    
    
    public String decrypt(byte[] ciphertext, String additionalData, byte[] iv) throws Exception {
    	GCMParameterSpec gcmSpec = new GCMParameterSpec(MAC_LENGTH, iv);
    	return super.decrypt(ciphertext, additionalData, gcmSpec);
    }
}
