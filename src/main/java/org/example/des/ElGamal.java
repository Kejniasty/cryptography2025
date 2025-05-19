package org.example.des;

import java.math.BigInteger;
import java.security.SecureRandom;

public class ElGamal {

    private final BigInteger privateKey;

    private BigInteger pKey;

    private BigInteger gKey;

    private BigInteger hKey;

    private final SecureRandom random = new SecureRandom();

    public ElGamal(BigInteger privateKey) {
        this.privateKey = privateKey;
    }

    public void generatePublicKeys(int bitLength) {
        this.pKey = generatePrime(bitLength, 40);
        this.gKey = new BigInteger(bitLength - 1, random).mod(pKey);
        this.hKey = gKey.modPow(privateKey, pKey);
    }

    // Miller-Rabin-based prime generation
    public BigInteger generatePrime(int bitLength, int certainty) {
        while (true) {
            BigInteger candidate = new BigInteger(bitLength, random).setBit(bitLength - 1).setBit(0);
            if (isProbablePrime(candidate, certainty)) {
                return candidate;
            }
        }
    }

    // Miller-Rabin Primality Test
    public boolean isProbablePrime(BigInteger n, int k) {
        if (n.equals(BigInteger.TWO) || n.equals(BigInteger.valueOf(3))) return true;
        if (n.compareTo(BigInteger.TWO) < 0 || n.mod(BigInteger.TWO).equals(BigInteger.ZERO)) return false;

        BigInteger d = n.subtract(BigInteger.ONE);
        int r = 0;
        while (d.mod(BigInteger.TWO).equals(BigInteger.ZERO)) {
            d = d.divide(BigInteger.TWO);
            r++;
        }

        for (int i = 0; i < k; i++) {
            BigInteger a = uniformRandom(BigInteger.TWO, n.subtract(BigInteger.TWO));
            BigInteger x = a.modPow(d, n);
            if (x.equals(BigInteger.ONE) || x.equals(n.subtract(BigInteger.ONE))) continue;

            boolean passed = false;
            for (int j = 0; j < r - 1; j++) {
                x = x.modPow(BigInteger.TWO, n);
                if (x.equals(n.subtract(BigInteger.ONE))) {
                    passed = true;
                    break;
                }
            }
            if (!passed) return false;
        }
        return true;
    }

    // Generate a random number in [min, max]
    private BigInteger uniformRandom(BigInteger min, BigInteger max) {
        BigInteger result;
        do {
            result = new BigInteger(max.bitLength(), random);
        } while (result.compareTo(min) < 0 || result.compareTo(max) > 0);
        return result;
    }

    // Encrypts a message m < p
    public BigInteger[] encryptBlock(byte[] messageBytes) {
        BigInteger m = new BigInteger(1, messageBytes); // Convert to BigInteger
        if (m.compareTo(pKey) >= 0) throw new IllegalArgumentException("Message too long");

        BigInteger y = new BigInteger(pKey.bitLength() - 1, random); // Ephemeral key
        BigInteger c1 = gKey.modPow(y, pKey);
        BigInteger s = hKey.modPow(y, pKey);
        BigInteger c2 = m.multiply(s).mod(pKey);

        return new BigInteger[]{c1, c2};
    }

    // Decrypts a ciphertext back to the message
    public byte[] decryptBlock(BigInteger c1, BigInteger c2) {
        BigInteger s = c1.modPow(privateKey, pKey);
        BigInteger sInv = s.modInverse(pKey);
        BigInteger m = c2.multiply(sInv).mod(pKey);
        return m.toByteArray(); // Convert back to bytes
    }

    //TODO: Dodać padding do bloków, obsłużyć to imo w klasie Data, do tego zastanowić się czy jakoś tego nie poprawić
    //TODO: Przeanalizować i ewentualnie zrobić refactor tego pliku (czy takie szyfrowanie jest na pewno najlepsze)
    //TODO: Ewentualnie poprawić jakieś skrajne przypadki, tzn. głównie m < pKey

}
