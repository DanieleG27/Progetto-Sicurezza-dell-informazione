package ciphers;



import javax.crypto.*;

import prngs.SecureRandomWrapper;

import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class CipherWrapper {

    private static final int KEY_SIZE = 256;

    private final Cipher cipher;
    private final SecretKey sk;

   
    protected CipherWrapper(String transformation, String keyGenAlgo, SecureRandomWrapper srw) throws Exception {
    	// Genera la chiave segreta utilizzando il metodo computeSecretKey
        this.sk = computeSecretKey(keyGenAlgo, srw.getSecureRandom());
        
        // Inizializza il cipher con la trasformazione data
        this.cipher = Cipher.getInstance(transformation);


    }
    
    protected CipherWrapper(String transformation, SecretKey secretKey) throws Exception {
        this.sk = secretKey;
        this.cipher = Cipher.getInstance(transformation);
    }

    
    private static SecretKey computeSecretKey(String keyGenAlgo, SecureRandom sr) throws Exception {
    	KeyGenerator keyGenerator = KeyGenerator.getInstance(keyGenAlgo);
        keyGenerator.init(KEY_SIZE, sr);  // Inizializza il generatore con la lunghezza della chiave
        return keyGenerator.generateKey();  // Restituisce la chiave generata
    }

   
    protected byte[] encrypt(String plaintext) throws Exception {
    	this.cipher.init(Cipher.ENCRYPT_MODE, sk);
    	return this.cipher.doFinal(plaintext.getBytes());
    }

    protected byte[] encrypt(String plaintext, AlgorithmParameterSpec spec) throws Exception {
    	cipher.init(Cipher.ENCRYPT_MODE, sk, spec);  // Inizializza il cipher in modalità di cifratura con parametri aggiuntivi
        return cipher.doFinal(plaintext.getBytes());  // Esegue la cifratura


    }

    protected byte[] encrypt(String plaintext, String additionalData, AlgorithmParameterSpec spec) throws Exception {
    	cipher.init(Cipher.ENCRYPT_MODE, sk, spec);  // Inizializza il cipher in modalità AEAD
        cipher.updateAAD(additionalData.getBytes());  // Aggiungi i dati extra al buffer interno
        return cipher.doFinal(plaintext.getBytes());  // Esegui la cifratura


    }

    protected String decrypt(byte[] ciphertext) throws Exception {
    	cipher.init(Cipher.DECRYPT_MODE, sk);  // Inizializza il cipher in modalità di decifratura
        byte[] decrypted = cipher.doFinal(ciphertext);  // Decifra il testo
        return new String(decrypted);  // Converte il risultato in una stringa


    }

    protected String decrypt(byte[] ciphertext, AlgorithmParameterSpec spec) throws Exception {
    	cipher.init(Cipher.DECRYPT_MODE, sk, spec);  // Inizializza il cipher in modalità di decifratura
        byte[] decrypted = cipher.doFinal(ciphertext);  // Decifra il testo
        return new String(decrypted);  // Converte il risultato in una stringa


    }

    protected String decrypt(byte[] ciphertext, String additionalData, AlgorithmParameterSpec spec) throws Exception {
    	cipher.init(Cipher.DECRYPT_MODE, sk, spec);  // Inizializza il cipher in modalità di decifratura
    	cipher.updateAAD(additionalData.getBytes());
    	byte[] decrypted = cipher.doFinal(ciphertext);  // Decifra il testo
        return new String(decrypted);  // Converte il risultato in una stringa


    }

}
