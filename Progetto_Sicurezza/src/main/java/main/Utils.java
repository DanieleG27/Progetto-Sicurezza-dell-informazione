package main;

import java.util.HexFormat;

public class Utils {

    /*
     * Method to convert a String into a byte array.
     */
    public static byte[] toByteArray(String input) {

        return input.getBytes();

    }

    /*
     * Method to convert a byte array into a hex string.
     */
    public static String toHexString(byte[] input) {

        return HexFormat.of().formatHex(input);

    }

    /*
     * Method to convert a hex string into a byte array.
     */
    public static byte[] fromHexString(String input) {

        return HexFormat.of().parseHex(input);

    }
    
    
    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            sb.append(String.format("%02X", bytes[i]));
            if ((i + 1) % 16 == 0) sb.append(" "); // per separare blocchi AES
        }
        return sb.toString();
    }

}
