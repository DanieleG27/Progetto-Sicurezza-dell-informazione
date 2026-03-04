package main;

import ciphers.RSACipherWrapper;

import java.security.*;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

public class MainAsymmetric {

    public static void main(String[] args) throws Exception {
        // === 1. Generare coppia di chiavi (RSA-512 — VULNERABILE) ===
        int keySize = 512; // VULNERABILITÀ: RSA-512 è insicura
        RSACipherWrapper rsaCipher = new RSACipherWrapper(keySize);
        PublicKey pubKey = rsaCipher.getPublicKey();
        PrivateKey privKey = rsaCipher.getPrivateKey();

        System.out.println("====== Chiavi generate (RSA " + keySize + ") ======");
        System.out.println("Chiave pubblica:  " + Base64.getEncoder().encodeToString(pubKey.getEncoded()));
        System.out.println("Chiave privata:   " + Base64.getEncoder().encodeToString(privKey.getEncoded()));

        // === 2. Cifrare un messaggio con la chiave pubblica ===
        String message = "Questo e' un messaggio segreto";
        byte[] encrypted = rsaCipher.encrypt(message);
        System.out.println("\n====== Cifratura / Decifratura ======");
        System.out.println("\nMessaggio cifrato (Base64): " + Base64.getEncoder().encodeToString(encrypted));

        // === 3. Decifrare con la chiave privata ===
        String decrypted = rsaCipher.decrypt(encrypted);
        System.out.println("Messaggio decifrato:         " + decrypted);

        // === 4. Firmare con la chiave privata ===
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privKey);
        signature.update(message.getBytes());
        byte[] sigBytes = signature.sign();
        System.out.println("\n====== Firma ======");
        System.out.println("\nFirma digitale (Base64): " + Base64.getEncoder().encodeToString(sigBytes));

        // === 5. Verificare la firma con la chiave pubblica ===
        Signature verifier = Signature.getInstance("SHA256withRSA");  
        verifier.initVerify(pubKey);
        verifier.update(message.getBytes());
        boolean verified = verifier.verify(sigBytes);
        System.out.println("Verifica firma: " + (verified ? "VALIDA " : "NON VALIDA "));

        // === 6. Mostrare la vulnerabilità RSA-512 ===
        System.out.println("\n====== [VULNERABILITA': RSA-512] ======");
        System.out.println("- Le chiavi RSA-512 sono deboli e possono essere fattorizzate pubblicamente.");
        System.out.println("- Ad esempio, il modulo n puo' essere inserito su https://factordb.com per recuperarne i fattori primi (p, q).");
        System.out.println("- Questo permette a un attaccante di ricostruire la chiave privata!\n");

        // Stampare il modulo n in esadecimale
        KeyFactory kf = KeyFactory.getInstance("RSA"); //per ricavare informazioni strutturate da una chiave
        RSAPublicKeySpec rsaSpec = kf.getKeySpec(pubKey, RSAPublicKeySpec.class); //estrae le specifiche RSA della chiave pubblica
        System.out.println("Modulo (n) da incollare su https://factordb.com (512):");
        System.out.println(rsaSpec.getModulus().toString(16));
        
        // === 7. Mostrare la robustezza di una chiave a 2048 bit ===
        keySize = 2048; 
        rsaCipher = new RSACipherWrapper(keySize);
        pubKey = rsaCipher.getPublicKey();
        rsaSpec = kf.getKeySpec(pubKey, RSAPublicKeySpec.class); //estrae le specifiche RSA della chiave pubblica
        System.out.println("\nModulo (n) da incollare su https://factordb.com (2048):");
        System.out.println(rsaSpec.getModulus().toString(16));
        
        
    }
}
