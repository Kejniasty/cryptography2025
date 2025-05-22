package org.example.des;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

public class DesData {
    private DES des;           // DES instance for single DES encryption
    private tripleDES tripleDES; // TripleDES instance for 3DES encryption

    // Constructor for single DES with one 64-bit key
    public DesData(long key) {
        this.des = new DES(key);
        this.tripleDES = null;
    }

    // Constructor for Triple DES with three 64-bit keys
    public DesData(long key1, long key2, long key3) {
        this.des = null;
        this.tripleDES = new tripleDES(key1, key2, key3);
    }

    // Load file content into a byte array
    public byte[] loadFile(String filePath) throws IOException {
        return Files.readAllBytes(Paths.get(filePath));
    }

    // Save byte array to a file
    public void saveFile(String filePath, byte[] data) throws IOException {
        Files.write(Paths.get(filePath), data);
    }

    // Convert 8 bytes to a 64-bit long value
    private long bytesToLong(byte[] bytes, int offset) {
        long result = 0;
        for (int i = 0; i < 8; i++) {
            result = (result << 8) | (bytes[offset + i] & 0xFF);
        }
        return result;
    }

    // Convert a 64-bit long value to 8 bytes
    private void longToBytes(long value, byte[] bytes, int offset) {
        for (int i = 7; i >= 0; i--) {
            bytes[offset + i] = (byte) (value & 0xFF);
            value >>>= 8;
        }
    }

    // Pad input data to a multiple of 8 bytes using PKCS5/PKCS7 padding
    private byte[] padInput(byte[] input) {
        int paddingLength = 8 - (input.length % 8); // Calculate padding length
        byte[] padded = new byte[input.length + paddingLength]; // New array with padding
        System.arraycopy(input, 0, padded, 0, input.length); // Copy original data
        for (int i = input.length; i < padded.length; i++) {
            padded[i] = (byte) paddingLength; // Fill padding with padding length value
        }
        return padded;
    }

    // Remove PKCS5/PKCS7 padding from decrypted data
    private byte[] unpadOutput(byte[] input) {
        int paddingLength = input[input.length - 1] & 0xFF; // Last byte indicates padding length
        if (paddingLength > 8 || paddingLength == 0) {
            throw new IllegalArgumentException("Invalid padding length: " + paddingLength);
        }
        return java.util.Arrays.copyOf(input, input.length - paddingLength); // Remove padding
    }

    // Encrypt a file using DES or Triple DES
    public void encryptFile(String inputFile, String outputFile) throws IOException {
        byte[] inputBytes = loadFile(inputFile); // Load the input file
        byte[] paddedBytes = padInput(inputBytes); // Add padding to align with 64-bit blocks
        byte[] outputBytes = new byte[paddedBytes.length]; // Output array for encrypted data

        // Process each 64-bit block
        for (int i = 0; i < paddedBytes.length; i += 8) {
            long block = bytesToLong(paddedBytes, i); // Convert 8 bytes to a 64-bit block
            long encrypted;
            encrypted = tripleDES.encryptBlock(block); // Use Triple DES
            longToBytes(encrypted, outputBytes, i); // Convert encrypted block back to bytes
        }

        saveFile(outputFile, outputBytes); // Save the encrypted data to file
    }

    // Decrypt a file using DES or Triple DES
    public void decryptFile(String inputFile, String outputFile) throws IOException {
        byte[] inputBytes = loadFile(inputFile); // Load the encrypted file
        byte[] outputBytes = new byte[inputBytes.length]; // Output array for decrypted data

        // Process each 64-bit block
        for (int i = 0; i < inputBytes.length; i += 8) {
            long block = bytesToLong(inputBytes, i); // Convert 8 bytes to a 64-bit block
            long decrypted;
            decrypted = tripleDES.decryptBlock(block); // Use Triple DES
            longToBytes(decrypted, outputBytes, i); // Convert decrypted block back to bytes
        }

        byte[] unpaddedBytes = unpadOutput(outputBytes); // Remove padding from decrypted data
        saveFile(outputFile, unpaddedBytes); // Save the decrypted data to file
    }
}