package org.example.des;

import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.SecureRandom;

public class AppController {

    @FXML
    private TextField key1Field, key2Field, key3Field;
    @FXML
    private TextField loadKeysField, saveKeysField;
    @FXML
    private TextField loadPlaintextField, loadCiphertextField;
    @FXML
    private TextField savePlaintextField, saveCiphertextField;
    @FXML
    private TextArea plaintextArea, ciphertextArea;
    @FXML
    private RadioButton fileRadio, windowRadio;

    private tripleDES tripleDES;
    private byte[] plaintextBytes, ciphertextBytes;

    @FXML
    private void initialize() {
        // Initialize radio buttons (default to "Okno")
        windowRadio.setSelected(true);
    }

    @FXML
    private void generateKeys() {
        // Use SecureRandom to generate random keys
        SecureRandom random = new SecureRandom();

        // Generate three 64-bit keys
        long key1 = generateRandomKey(random);
        long key2 = generateRandomKey(random);
        long key3 = generateRandomKey(random);
        // Display the keys in hex format
        key1Field.setText(String.format("%016X", key1));
        key2Field.setText(String.format("%016X", key2));
        key3Field.setText(String.format("%016X", key3));
    }

    @FXML
    // Helper method to generate a random 64-bit key with parity adjustment
    private long generateRandomKey(SecureRandom random) {
        // Generate a random 64-bit key
        long key = random.nextLong();

        // Adjust parity for each byte (DES keys typically have odd parity)
        key = adjustParity(key);

        return key;
    }

    // Adjust parity of each byte in the 64-bit key to have an odd number of 1s
    private long adjustParity(long key) {
        long adjustedKey = 0;
        for (int i = 0; i < 8; i++) {
            // Extract each byte (8 bits) from the 64-bit key
            byte b = (byte) ((key >>> (i * 8)) & 0xFF);

            // Count the number of 1s in the first 7 bits
            int bitCount = Integer.bitCount(b & 0xFE); // Ignore the least significant bit (parity bit)

            // Set the parity bit (LSB) to ensure odd parity
            if (bitCount % 2 == 0) {
                // If the number of 1s is even, set the parity bit to 1 to make it odd
                b |= 0x01;
            } else {
                // If the number of 1s is odd, set the parity bit to 0
                b &= 0xFE;
            }

            // Add the adjusted byte back to the key
            adjustedKey |= ((long) (b & 0xFF) << (i * 8));
        }
        return adjustedKey;
    }

    @FXML
    private void loadKeys() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Wczytaj klucze z pliku");
        fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("Plik klucza TripleDES", "*.3desKey"));
        File file = fileChooser.showOpenDialog(new Stage());
        if (file != null) {
            try {
                String[] keys = new String(Files.readAllBytes(file.toPath())).split("\n");
                if (keys.length >= 3) {
                    key1Field.setText(keys[0].trim());
                    key2Field.setText(keys[1].trim());
                    key3Field.setText(keys[2].trim());
                    loadKeysField.setText(file.getAbsolutePath());
                } else {
                    showAlert("Błąd", "Plik kluczy musi zawierać dokładnie 3 klucze w formacie hex!");
                }
            } catch (IOException e) {
                showAlert("Błąd", "Problem z wczytaniem pliku kluczy: " + e.getMessage());
            }
        }
    }

    @FXML
    private void saveKeys() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Zapisz klucze do pliku");
        fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("Plik klucza TripleDES", "*.3desKey"));
        File file = fileChooser.showSaveDialog(new Stage());
        if (file != null) {
            try {
                String keys = key1Field.getText() + "\n" + key2Field.getText() + "\n" + key3Field.getText();
                Files.write(file.toPath(), keys.getBytes());
                saveKeysField.setText(file.getAbsolutePath());
            } catch (IOException e) {
                showAlert("Błąd", "Problem z zapisem pliku kluczy: " + e.getMessage());
            }
        }
    }

    @FXML
    private void loadPlaintext() {

        if (windowRadio.isSelected()) {
            showAlert("Informacja", "Wybrałeś tryb okna! W trybie okna nie możesz wczytywać plików.");
            return;
        }

        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Otwórz plik z tekstem jawnym");
        File file = fileChooser.showOpenDialog(new Stage());
        if (file != null) {
            try {
                plaintextBytes = Files.readAllBytes(file.toPath());
                plaintextArea.setText(new String(plaintextBytes));
                loadPlaintextField.setText(file.getAbsolutePath());
            } catch (IOException e) {
                showAlert("Błąd", "Problem z wczytaniem pliku: " + e.getMessage());
            }
        }
    }

    @FXML
    private void loadCiphertext() {

        if (windowRadio.isSelected()) {
            showAlert("Informacja", "Wybrałeś tryb okna! W trybie okna nie możesz wczytywać plików.");
            return;
        }

        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Otwórz plik z szyfrogramem");
        File file = fileChooser.showOpenDialog(new Stage());
        if (file != null) {
            try {
                ciphertextBytes = Files.readAllBytes(file.toPath());
                ciphertextArea.setText(bytesToHex(ciphertextBytes));
                loadCiphertextField.setText(file.getAbsolutePath());
            } catch (IOException e) {
                showAlert("Błąd", "Problem z wczytaniem pliku: " + e.getMessage());
            }
        }
    }

    @FXML
    private void encrypt() {
        try {
            // Initialize TripleDES with the keys
            long key1 = Long.parseUnsignedLong(key1Field.getText(), 16);
            long key2 = Long.parseUnsignedLong(key2Field.getText(), 16);
            long key3 = Long.parseUnsignedLong(key3Field.getText(), 16);
            tripleDES = new tripleDES(key1, key2, key3);

            byte[] input;
            if (fileRadio.isSelected()) {
                if (plaintextBytes == null || plaintextBytes.length == 0) {
                    showAlert("Błąd", "Wybrałeś szyfrowanie z pliku! Najpierw wczytaj plik z tekstem jawnym.");
                    return;
                }
                input = plaintextBytes;
            } else {
                input = plaintextArea.getText().getBytes();
            }
            // Pad input to be a multiple of 8 bytes
            input = padInput(input);
            byte[] output = new byte[input.length];
            // Encrypt in 8-byte blocks
            for (int i = 0; i < input.length; i += 8) {
                long block = bytesToLong(input, i);
                long encrypted = tripleDES.encryptBlock(block);
                longToBytes(encrypted, output, i);
            }
            ciphertextBytes = output;
            ciphertextArea.setText(bytesToHex(ciphertextBytes));
        } catch (NumberFormatException e) {
            showAlert("Błąd", "Nieprawidłowy format kluczy! Użyj wartości hex (np. 0123456789ABCDEF)");
        }
    }

    @FXML
    private void decrypt() {
        try {
            // Initialize TripleDES with the keys
            long key1 = Long.parseUnsignedLong(key1Field.getText(), 16);
            long key2 = Long.parseUnsignedLong(key2Field.getText(), 16);
            long key3 = Long.parseUnsignedLong(key3Field.getText(), 16);
            tripleDES = new tripleDES(key1, key2, key3);

            byte[] input;
            if (fileRadio.isSelected()) {
                if (plaintextBytes == null || plaintextBytes.length == 0) {
                    showAlert("Błąd", "Wybrałeś deszyfrowanie z pliku! Najpierw wczytaj plik z szyfrogramem.");
                    return;
                }
                input = plaintextBytes;
            } else {
                input = hexToBytes(ciphertextArea.getText());
            }

            // Ensure input is a multiple of 8 bytes
            if (input.length % 8 != 0) {
                showAlert("Błąd", "Szyfrogram musi mieć długość będącą wielokrotnością 8 bajtów!");
                return;
            }

            byte[] output = new byte[input.length];
            // Decrypt in 8-byte blocks
            for (int i = 0; i < input.length; i += 8) {
                long block = bytesToLong(input, i);
                long decrypted = tripleDES.decryptBlock(block);
                longToBytes(decrypted, output, i);
            }
            // Remove padding
            output = unpadOutput(output);
            plaintextBytes = output;
            plaintextArea.setText(new String(plaintextBytes));
        } catch (NumberFormatException e) {
            showAlert("Błąd", "Nieprawidłowy format kluczy lub szyfrogramu! Użyj wartości hex.");
        }
    }

    @FXML
    private void savePlaintext() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Zapisz plik z tekstem jawnym");
        File file = fileChooser.showSaveDialog(new Stage());
        if (file != null) {
            try {
                if (plaintextBytes == null) {
                    plaintextBytes = plaintextArea.getText().getBytes();
                }
                Files.write(file.toPath(), plaintextBytes);
                savePlaintextField.setText(file.getAbsolutePath());
            } catch (IOException e) {
                showAlert("Błąd", "Problem z zapisem pliku: " + e.getMessage());
            }
        }
    }

    @FXML
    private void saveCiphertext() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Zapisz plik z szyfrogramem");
        File file = fileChooser.showSaveDialog(new Stage());
        if (file != null) {
            try {
                if (ciphertextBytes == null) {
                    ciphertextBytes = hexToBytes(ciphertextArea.getText());
                }
                Files.write(file.toPath(), ciphertextBytes);
                saveCiphertextField.setText(file.getAbsolutePath());
            } catch (NumberFormatException e) {
                showAlert("Błąd", "Nieprawidłowy format szyfrogramu w oknie!");
            } catch (IOException e) {
                showAlert("Błąd", "Problem z zapisem pliku: " + e.getMessage());
            }
        }
    }

    // Helper methods for encryption/decryption
    private long bytesToLong(byte[] bytes, int offset) {
        long result = 0;
        for (int i = 0; i < 8; i++) {
            result = (result << 8) | (bytes[offset + i] & 0xFF);
        }
        return result;
    }

    private void longToBytes(long value, byte[] bytes, int offset) {
        for (int i = 7; i >= 0; i--) {
            bytes[offset + i] = (byte) (value & 0xFF);
            value >>>= 8;
        }
    }

    private byte[] padInput(byte[] input) {
        int paddingLength = 8 - (input.length % 8);
        if (paddingLength == 8) paddingLength = 0; // No padding needed if already a multiple of 8
        byte[] padded = new byte[input.length + paddingLength];
        System.arraycopy(input, 0, padded, 0, input.length);
        for (int i = input.length; i < padded.length; i++) {
            padded[i] = (byte) paddingLength;
        }
        return padded;
    }

    private byte[] unpadOutput(byte[] input) {
        int paddingLength = input[input.length - 1] & 0xFF;
        if (paddingLength > 8 || paddingLength == 0) return input; // No padding or invalid
        return java.util.Arrays.copyOf(input, input.length - paddingLength);
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    private byte[] hexToBytes(String hex) {
        hex = hex.replaceAll("\\s+", ""); // Remove spaces
        byte[] bytes = new byte[hex.length() / 2];
        for (int i = 0; i < hex.length(); i += 2) {
            bytes[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
        }
        return bytes;
    }

    private void showAlert(String title, String message) {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
    }

    @FXML
    private void clearPlainTextArea() {
        plaintextArea.clear();

        plaintextBytes = null;
    }

    @FXML
    private void clearCipherTextAreas() {
        ciphertextArea.clear();

        ciphertextBytes = null;
    }
}