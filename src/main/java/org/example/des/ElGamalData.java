package org.example.des;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;

public class ElGamalData {
    private final int blockSize;
    private final ElGamal elGamal;

    public ElGamalData(ElGamal elGamal) {
        this.elGamal = elGamal;
        this.blockSize = (elGamal.getPKey().bitLength() / 8) - 1;
        if (blockSize < 16) {
            throw new IllegalArgumentException("Klucz zbyt mały dla bezpiecznego rozmiaru bloku");
        }
    }

    public byte[] loadFile(String filePath) throws IOException {
        return Files.readAllBytes(Paths.get(filePath));
    }

    public void saveFile(String filePath, byte[] data) throws IOException {
        Files.write(Paths.get(filePath), data);
    }

    public long bytesToLong(byte[] bytes, int offset) {
        if (offset + 8 > bytes.length) {
            throw new IllegalArgumentException("Za mało bajtów do konwersji na long");
        }
        long value = 0;
        for (int i = 0; i < 8; i++) {
            value = (value << 8) | (bytes[offset + i] & 0xFF);
        }
        return value;
    }

    public void longToBytes(long value, byte[] bytes, int offset) {
        if (offset + 8 > bytes.length) {
            throw new IllegalArgumentException("Tablica bajtów za mała");
        }
        for (int i = 7; i >= 0; i--) {
            bytes[offset + i] = (byte) (value & 0xFF);
            value >>= 8;
        }
    }

    public byte[] padInput(byte[] input) {
        if (input == null) {
            throw new IllegalArgumentException("Dane wejściowe nie mogą być null");
        }
        int paddingLength = blockSize - (input.length % blockSize);
        if (paddingLength == 0) {
            paddingLength = blockSize;
        }
        byte[] padded = new byte[input.length + paddingLength];
        System.arraycopy(input, 0, padded, 0, input.length);
        for (int i = input.length; i < padded.length; i++) {
            padded[i] = (byte) paddingLength;
        }
        return padded;
    }

    public byte[] unpadOutput(byte[] input) {
        if (input == null || input.length == 0 || input.length % blockSize != 0) {
            throw new IllegalArgumentException("Nieprawidłowe dane wejściowe");
        }
        int paddingLength = input[input.length - 1] & 0xFF;
        if (paddingLength < 1 || paddingLength > blockSize) {
            throw new IllegalArgumentException("Nieprawidłowe dopełnienie");
        }
        for (int i = input.length - paddingLength; i < input.length; i++) {
            if (input[i] != (byte) paddingLength) {
                throw new IllegalArgumentException("Nieprawidłowe dopełnienie");
            }
        }
        byte[] unpadded = new byte[input.length - paddingLength];
        System.arraycopy(input, 0, unpadded, 0, unpadded.length);
        return unpadded;
    }

    public void encryptFile(String inputFile, String outputFile) throws IOException {
        byte[] input = loadFile(inputFile);
        byte[] padded = padInput(input);
        int blockCount = padded.length / blockSize;
        BigInteger[][] ciphertexts = new BigInteger[blockCount][2];
        for (int i = 0; i < blockCount; i++) {
            byte[] block = new byte[blockSize];
            System.arraycopy(padded, i * blockSize, block, 0, blockSize);
            ciphertexts[i] = elGamal.encryptBlock(block);
        }
        byte[] output = serializeCiphertexts(ciphertexts);
        saveFile(outputFile, output);
    }

    public void decryptFile(String inputFile, String outputFile) throws IOException {
        byte[] input = loadFile(inputFile);
        BigInteger[][] ciphertexts = deserializeCiphertexts(input);
        byte[] decrypted = new byte[ciphertexts.length * blockSize];
        for (int i = 0; i < ciphertexts.length; i++) {
            byte[] block = elGamal.decryptBlock(ciphertexts[i][0], ciphertexts[i][1]);
            System.arraycopy(block, 0, decrypted, i * blockSize, blockSize);
        }
        byte[] unpadded = unpadOutput(decrypted);
        saveFile(outputFile, unpadded);
    }

    byte[] serializeCiphertexts(BigInteger[][] ciphertexts) {
        int totalLength = 8;
        for (BigInteger[] ciphertext : ciphertexts) {
            totalLength += 4 + ciphertext[0].toByteArray().length + ciphertext[1].toByteArray().length;
        }
        byte[] output = new byte[totalLength];
        int offset = 0;
        longToBytes(ciphertexts.length, output, offset);
        offset += 8;
        for (BigInteger[] ciphertext : ciphertexts) {
            byte[] c1Bytes = ciphertext[0].toByteArray();
            byte[] c2Bytes = ciphertext[1].toByteArray();
            longToBytes(c1Bytes.length, output, offset);
            offset += 4;
            System.arraycopy(c1Bytes, 0, output, offset, c1Bytes.length);
            offset += c1Bytes.length;
            System.arraycopy(c2Bytes, 0, output, offset, c2Bytes.length);
            offset += c2Bytes.length;
        }
        return output;
    }

    BigInteger[][] deserializeCiphertexts(byte[] input) {
        int offset = 0;
        long blockCount = bytesToLong(input, offset);
        offset += 8;
        BigInteger[][] ciphertexts = new BigInteger[(int) blockCount][2];
        for (int i = 0; i < blockCount; i++) {
            long c1Length = bytesToLong(input, offset);
            offset += 4;
            byte[] c1Bytes = new byte[(int) c1Length];
            System.arraycopy(input, offset, c1Bytes, 0, (int) c1Length);
            offset += c1Length;
            byte[] c2Bytes = new byte[input.length - offset];
            System.arraycopy(input, offset, c2Bytes, 0, c2Bytes.length);
            offset += c2Bytes.length;
            ciphertexts[i][0] = new BigInteger(1, c1Bytes);
            ciphertexts[i][1] = new BigInteger(1, c2Bytes);
        }
        return ciphertexts;
    }
    public int getBlockSize() {
        return 256; // lub inna wartość zgodna z Twoim paddingiem, np. 128, 256 dla ElGamala
    }
}