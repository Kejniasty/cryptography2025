package org.example.des;

import java.math.BigInteger;
import java.security.SecureRandom;

public class ElGamal {
    private final BigInteger privateKey;
    private BigInteger pKey; // Liczba pierwsza (moduł)
    private BigInteger gKey; // Generator
    private BigInteger hKey; // Klucz publiczny: g^privateKey mod p
    private final SecureRandom random = new SecureRandom();
    private final int certainty = 40; // Pewność testu Millera-Rabina

    public ElGamal(BigInteger privateKey, int bitLength) {
        if (privateKey.compareTo(BigInteger.ZERO) <= 0) {
            throw new IllegalArgumentException("Klucz prywatny musi być dodatni");
        }
        this.privateKey = privateKey;
        generatePublicKeys(bitLength);
    }

    public void generatePublicKeys(int bitLength) {
        if (bitLength < 2048) {
            throw new IllegalArgumentException("Długość bitowa musi wynosić co najmniej 2048 dla bezpieczeństwa");
        }
        // Generuj bezpieczną liczbę pierwszą: p = 2q + 1
        BigInteger q;
        do {
            q = generatePrime(bitLength - 1, certainty);
            this.pKey = q.multiply(BigInteger.TWO).add(BigInteger.ONE);
        } while (!isProbablePrime(pKey, certainty));

        // Wybierz generator grupy
        this.gKey = findGenerator(pKey);
        this.hKey = gKey.modPow(privateKey, pKey);
    }

    private BigInteger findGenerator(BigInteger p) {
        BigInteger q = p.subtract(BigInteger.ONE).divide(BigInteger.TWO);
        BigInteger g;
        do {
            g = new BigInteger(p.bitLength() - 1, random).mod(p);
        } while (g.modPow(q, p).equals(BigInteger.ONE) || g.equals(BigInteger.ZERO));
        return g;
    }

    public BigInteger generatePrime(int bitLength, int certainty) {
        while (true) {
            BigInteger candidate = new BigInteger(bitLength, random).setBit(bitLength - 1).setBit(0);
            if (isProbablePrime(candidate, certainty)) {
                return candidate;
            }
        }
    }

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

    private BigInteger uniformRandom(BigInteger min, BigInteger max) {
        BigInteger result;
        do {
            result = new BigInteger(max.bitLength(), random);
        } while (result.compareTo(min) < 0 || result.compareTo(max) > 0);
        return result;
    }

    public BigInteger[] encryptBlock(byte[] messageBytes) {
        if (messageBytes.length > pKey.bitLength() / 8 - 1) {
            throw new IllegalArgumentException("Blok wiadomości za długi dla klucza");
        }
        BigInteger m = new BigInteger(1, messageBytes);
        if (m.compareTo(pKey) >= 0) {
            throw new IllegalArgumentException("Wiadomość za duża dla modułu");
        }
        BigInteger y = new BigInteger(pKey.bitLength() - 1, random);
        BigInteger c1 = gKey.modPow(y, pKey);
        BigInteger s = hKey.modPow(y, pKey);
        BigInteger c2 = m.multiply(s).mod(pKey);
        return new BigInteger[]{c1, c2};
    }

    public byte[] decryptBlock(BigInteger c1, BigInteger c2) {
        if (c1.compareTo(BigInteger.ZERO) <= 0 || c1.compareTo(pKey) >= 0 ||
                c2.compareTo(BigInteger.ZERO) <= 0 || c2.compareTo(pKey) >= 0) {
            throw new IllegalArgumentException("Nieprawidłowy szyfrogram");
        }
        BigInteger s = c1.modPow(privateKey, pKey);
        BigInteger sInv = s.modInverse(pKey);
        BigInteger m = c2.multiply(sInv).mod(pKey);
        byte[] result = m.toByteArray();
        int expectedBlockSize = (pKey.bitLength() / 8) - 1;
        if (result.length > expectedBlockSize) {
            if (result[0] == 0) {
                byte[] trimmed = new byte[result.length - 1];
                System.arraycopy(result, 1, trimmed, 0, trimmed.length);
                result = trimmed;
            } else {
                throw new IllegalStateException("Zdeszyfrowany blok za duży");
            }
        }
        if (result.length < expectedBlockSize) {
            byte[] padded = new byte[expectedBlockSize];
            System.arraycopy(result, 0, padded, expectedBlockSize - result.length, result.length);
            result = padded;
        }
        return result;
    }

    public BigInteger getPKey() { return pKey; }
    public BigInteger getGKey() { return gKey; }
    public BigInteger getHKey() { return hKey; }
}
