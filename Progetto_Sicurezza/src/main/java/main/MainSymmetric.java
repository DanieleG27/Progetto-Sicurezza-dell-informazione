package main;


import java.util.Arrays;
import java.util.Base64;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.util.Base64;

import ciphers.AESCBCChiperWrapper;
import ciphers.AESECBCipherWrapper;
import ciphers.AESGCMCipherWrapper;
import ciphers.ChaCha20CipherWrapper;
import prngs.SecureRandomWrapper;

public class MainSymmetric {
	public static void main(String[] args) throws Exception {
        SecureRandomWrapper srw = new SecureRandomWrapper("SHA1PRNG");

        // ======================== ECB ============================
        AESECBCipherWrapper ecbCipher = new AESECBCipherWrapper(srw);
        String ecbPlaintext = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 32 byte
        byte[] ecbCiphertext = ecbCipher.encrypt(ecbPlaintext);
        String ecbDecrypted = ecbCipher.decrypt(ecbCiphertext);

        System.out.println("\n=== AES ECB Mode ===");
        System.out.println("Plaintext:    " + ecbPlaintext);
        System.out.println("Ciphertext:   " + Utils.bytesToHex(ecbCiphertext));
        System.out.println("Decrypted:    " + ecbDecrypted);
        System.out.println("[VULNERABILITA'] In ECB blocchi di testo in chiaro uguali corrispondono a blocchi di testo cifrato identici.\n");

        // ======================== CBC con IV fisso ============================
        byte[] fixedIV = srw.generateIV();
        AESCBCChiperWrapper cbcFixed = new AESCBCChiperWrapper(srw, fixedIV);
        String cbcText = "Messaggio da cifrare";

        byte[] cbcCiphertext1 = cbcFixed.encrypt(cbcText);
        byte[] cbcCiphertext2 = cbcFixed.encrypt(cbcText);

        System.out.println("\n=== AES CBC con IV fisso ===");
        System.out.println("Cifrato #1:   " + Base64.getEncoder().encodeToString(cbcCiphertext1));
        System.out.println("Cifrato #2:   " + Base64.getEncoder().encodeToString(cbcCiphertext2));
        System.out.println("Uguali?       " + Arrays.equals(cbcCiphertext1, cbcCiphertext2));
        System.out.println("[VULNERABILITA'] IV fisso → messaggi identici → ciphertext identici."
        		+ "Non viene sfruttata la imprevedibilia' del CBC che nasce per superare il determinismo di ECB\n");

        // ======================== CBC con IV random (corretto) ============================
        AESCBCChiperWrapper cbcRandom1 = new AESCBCChiperWrapper(srw);
        AESCBCChiperWrapper cbcRandom2 = new AESCBCChiperWrapper(srw);
        byte[] ct1 = cbcRandom1.encrypt(cbcText);
        byte[] ct2 = cbcRandom2.encrypt(cbcText);

        System.out.println("\n=== AES CBC con IV casuale ===");
        System.out.println("Cifrato #1:   " + Base64.getEncoder().encodeToString(ct1));
        System.out.println("Cifrato #2:   " + Base64.getEncoder().encodeToString(ct2));
        System.out.println("Uguali?       " + Arrays.equals(ct1, ct2));
        System.out.println("[SICURO] IV diverso → ciphertext diverso anche se il plaintext è lo stesso.\n");

        // ======================== GCM AEAD Integrity Test ============================
        AESGCMCipherWrapper gcm = new AESGCMCipherWrapper(srw);
        byte[] gcmIV = srw.generateIV();
        String message = "Messaggio importante";
        String aad = "dati-auth";

        byte[] gcmEncrypted = gcm.encrypt(message, aad, gcmIV);

        System.out.println("\n=== AES GCM con AAD ===");
        System.out.println("Ciphertext:   " + Base64.getEncoder().encodeToString(gcmEncrypted));
        try {
            String output = gcm.decrypt(gcmEncrypted, "dati-auth", gcmIV);
            System.out.println("Decrypted:    " + output);
            System.out.println("[SICURO] AAD corretto → decrittazione riuscita.");
        } catch (Exception e) {
            System.out.println("[ERRORE] Decifrazione fallita con AAD valido.");
        }

        // Simulazione di manomissione dell'AAD
        try {
            gcm.decrypt(gcmEncrypted, "manomesso", gcmIV);
            System.out.println("[ERRORE] Decrittazione riuscita con AAD errato (dovrebbe fallire).");
        } catch (Exception e) {
            System.out.println("[OK] AAD modificato -> decrittazione fallita -> integrità garantita.\n");
        }

        // ======================== ChaCha20: riuso IV + counter ============================
        /*
         * Java non permette la ri-inizializzazione con la stessa chiave e lo stesso nonce dello stesso cifrario,
         * quindi ne creo 2 e li inizializzo alla stessa maniera
         */
        
        byte[] nonce = srw.generateIV12Byte(); // 12 byte
        int counter = 1;
        
        ChaCha20CipherWrapper chacha1 = new ChaCha20CipherWrapper(srw);
        ChaCha20CipherWrapper chacha2 = new ChaCha20CipherWrapper(srw);

        byte[] chachaCt1 = chacha1.encrypt("Segreto1", nonce, counter);
        byte[] chachaCt2 = chacha2.encrypt("Segreto1", nonce, counter);

        System.out.println("\n=== ChaCha20 con nonce/counter riusati ===");
        System.out.println("Ciphertext #1: " + Base64.getEncoder().encodeToString(chachaCt1));
        System.out.println("Ciphertext #2: " + Base64.getEncoder().encodeToString(chachaCt2));
        System.out.println("Uguali?        " + Arrays.equals(chachaCt1, chachaCt2));
        System.out.println("[ROBUSTEZZA] Nonce/counter riusati -> cifrati comunque diversi.\n");
        
        
     // ======================== ChaCha20: riuso IV + counter e secret key ============================
        
        byte[] fixedKeyBytes = new byte[32]; // 256 bit chiave fissa
        Arrays.fill(fixedKeyBytes, (byte)0x01); // valore qualsiasi per esempio

        SecretKey fixedKey = new SecretKeySpec(fixedKeyBytes, "AES");

        chacha1 = new ChaCha20CipherWrapper(fixedKey);
        chacha2 = new ChaCha20CipherWrapper(fixedKey);

        nonce = srw.generateIV12Byte(); // 12 byte nonce
        counter = 1;

        chachaCt1 = chacha1.encrypt("Segreto1", nonce, counter);
        chachaCt2 = chacha2.encrypt("Segreto1", nonce, counter);

        System.out.println("\n=== ChaCha20 con chiave/nonce/counter riusati ===");
        System.out.println("Ciphertext #1: " + Base64.getEncoder().encodeToString(chachaCt1));
        System.out.println("Ciphertext #2: " + Base64.getEncoder().encodeToString(chachaCt2));
        System.out.println("Uguali?        " + Arrays.equals(chachaCt1, chachaCt2));
        System.out.println("[VULNERABILITA'] Riutilizzo di chiave/nonce/counter => riuso keystream => grave rischio!\n");
    }
}

