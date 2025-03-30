package org.example.des;

public class tripleDES {
    private DES des1; // DES instance with key K1
    private DES des2; // DES instance with key K2
    private DES des3; // DES instance with key K3

    // Constructor accepting three 64-bit keys for Triple DES
    public tripleDES(long key1, long key2, long key3) {
        this.des1 = new DES(key1); // Initialize DES with K1 for first encryption
        this.des2 = new DES(key2); // Initialize DES with K2 for decryption
        this.des3 = new DES(key3); // Initialize DES with K3 for second encryption
    }

    // Encrypt a 64-bit block using EDE scheme
    public long encryptBlock(long block) {
        long step1 = des3.encryptBlock(block);  // Step 1: Encrypt with K3
        long step2 = des2.decryptBlock(step1);  // Step 2: Decrypt with K2
        long step3 = des1.encryptBlock(step2);  // Step 3: Encrypt with K1
        return step3;                           // Return the encrypted block
    }

    // Decrypt a 64-bit block using DED
    public long decryptBlock(long block) {
        long step1 = des1.decryptBlock(block);  // Step 1: Decrypt with K1
        long step2 = des2.encryptBlock(step1);  // Step 2: Encrypt with K2
        long step3 = des3.decryptBlock(step2);  // Step 3: Decrypt with K3
        return step3;                           // Return the decrypted block
    }
    // TODO: test the algorithm
}