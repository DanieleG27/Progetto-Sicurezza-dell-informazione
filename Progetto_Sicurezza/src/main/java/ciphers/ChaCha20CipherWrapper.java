package ciphers;

import javax.crypto.SecretKey;
import javax.crypto.spec.ChaCha20ParameterSpec;

import prngs.SecureRandomWrapper;

public class ChaCha20CipherWrapper extends CipherWrapper {


    public ChaCha20CipherWrapper(SecureRandomWrapper srw) throws Exception {
    	
    	super("CHACHA20", "AES", srw);


    }
    
    public ChaCha20CipherWrapper(SecretKey fixedKey) throws Exception {
        super("CHACHA20", fixedKey);
    }

  
    public byte[] encrypt(String plaintext, byte[] iv, int counter) throws Exception {
    	ChaCha20ParameterSpec spec = new ChaCha20ParameterSpec(iv, counter);
    	return super.encrypt(plaintext, spec);
    }

    public String decrypt(byte[] ciphertext, byte[] iv, int counter) throws Exception {
    	ChaCha20ParameterSpec spec = new ChaCha20ParameterSpec(iv, counter);
    	return super.decrypt(ciphertext, spec);
    }

}
