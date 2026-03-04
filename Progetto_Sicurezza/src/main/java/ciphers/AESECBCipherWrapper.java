package ciphers;

import prngs.SecureRandomWrapper;

public class AESECBCipherWrapper extends CipherWrapper {

	public AESECBCipherWrapper(SecureRandomWrapper srw) throws Exception {
	    super("AES/ECB/PKCS5Padding", "AES", srw); // Inizializza CipherWrapper con AES in modalità ECB e PKCS5Padding
	}


    public byte[] encrypt(String plaintext) throws Exception {
    	return super.encrypt(plaintext); 


    }

   
    public String decrypt(byte[] ciphertext) throws Exception {
        return super.decrypt(ciphertext);  // Usa il metodo della superclasse per decifrare il testo cifrato

    }
}
