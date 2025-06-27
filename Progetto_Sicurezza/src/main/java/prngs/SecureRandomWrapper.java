package prngs;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class SecureRandomWrapper {

    private final SecureRandom sr;

 
    public SecureRandomWrapper(String algorithm) throws NoSuchAlgorithmException {
    	this.sr = SecureRandom.getInstance(algorithm);


    }

   
    public void changeSeed(int seed) {
    	sr.setSeed(seed);

    }
    
    public int getRandomInt() {
    	return sr.nextInt();

    }

    public void fillByteArray(byte[] input) {
    	sr.nextBytes(input);

    }

    public SecureRandom getSecureRandom() {
    	return this.sr;

    }
    
    public byte[] generateIV() {
        byte[] iv = new byte[16]; // 128-bit IV for AES
        sr.nextBytes(iv);
        return iv;
    }
    
    public byte[] generateIV12Byte() {
        byte[] iv = new byte[12]; // 128-bit IV for AES
        sr.nextBytes(iv);
        return iv;
    }
}
