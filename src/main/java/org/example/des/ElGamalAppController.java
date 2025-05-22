package org.example.des;

import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;

import static java.nio.file.Files.write;

public class ElGamalAppController {

    public Button savePlaintextButton;
    public Button saveCiphertextButton;
    @FXML
    private TextField key1Field, key2Field, key3Field, modNField; // g, h, a, p (MOD N)
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
    @FXML
    private Button generateKeysButton; // Dodajemy referencję do przycisku

    private ElGamal elGamal;
    private ElGamalData data;
    private byte[] plaintextBytes, ciphertextBytes;

    @FXML
    private void initialize() {
        windowRadio.setSelected(true);
    }

    @FXML
    private void generateKeys() {
        // Wyłączamy przycisk podczas generowania
        generateKeysButton.setDisable(true);
        showInfoAlert("Informacja", "Generowanie kluczy, proszę czekać...");

        // Tworzymy zadanie asynchroniczne
        Task<Void> generateKeysTask = new Task<>() {
            @Override
            protected Void call() throws Exception {
                try {
                    System.out.println("Rozpoczynanie generowania kluczy...");
                    BigInteger privateKey = new BigInteger(key3Field.getText().isEmpty() ? "12345678901234567890" : key3Field.getText());
                    System.out.println("Klucz prywatny: " + privateKey.toString(16));
                    elGamal = new ElGamal(privateKey, 2048); // 2048 bitów
                    data = new ElGamalData(elGamal);
                    System.out.println("ElGamal zainicjalizowany");

                    // Aktualizacja UI w wątku JavaFX
                    javafx.application.Platform.runLater(() -> {
                        if (elGamal.getGKey() != null) {
                            key1Field.setText(elGamal.getGKey().toString(16)); // g
                            System.out.println("g: " + elGamal.getGKey().toString(16));
                        } else {
                            System.out.println("Błąd: getGKey() zwróciło null");
                            showAlert("Błąd", "Metoda getGKey() nie działa poprawnie!");
                        }
                        if (elGamal.getHKey() != null) {
                            key2Field.setText(elGamal.getHKey().toString(16)); // h
                            System.out.println("h: " + elGamal.getHKey().toString(16));
                        } else {
                            System.out.println("Błąd: getHKey() zwróciło null");
                            showAlert("Błąd", "Metoda getHKey() nie działa poprawnie!");
                        }
                        if (elGamal.getPKey() != null) {
                            modNField.setText(elGamal.getPKey().toString(16)); // p (MOD N)
                            System.out.println("p: " + elGamal.getPKey().toString(16));
                        } else {
                            System.out.println("Błąd: getPKey() zwróciło null");
                            showAlert("Błąd", "Metoda getPKey() nie działa poprawnie!");
                        }
                        key3Field.setText(privateKey.toString(16)); // a
                        System.out.println("a: " + privateKey.toString(16));
                        System.out.println("Klucze wygenerowane pomyślnie");
                    });
                } catch (NumberFormatException e) {
                    System.out.println("Błąd NumberFormatException: " + e.getMessage());
                    javafx.application.Platform.runLater(() -> showAlert("Błąd", "Nieprawidłowy klucz prywatny!"));
                } catch (Exception e) {
                    System.out.println("Błąd ogólny: " + e.getMessage());
                    javafx.application.Platform.runLater(() -> showAlert("Błąd", "Błąd podczas generowania kluczy: " + e.getMessage()));
                }
                return null;
            }
        };

        // Obsługa zakończenia zadania
        generateKeysTask.setOnSucceeded(event -> {
            generateKeysButton.setDisable(false);
            System.out.println("Generowanie zakończone pomyślnie");
        });
        generateKeysTask.setOnFailed(event -> {
            generateKeysButton.setDisable(false);
            System.out.println("Generowanie nie powiodło się: " + generateKeysTask.getException());
            showAlert("Błąd", "Nie udało się wygenerować kluczy: " + generateKeysTask.getException().getMessage());
        });

        // Uruchomienie zadania w oddzielnym wątku
        new Thread(generateKeysTask).start();
    }

    @FXML
    private void loadKeys() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Wczytaj klucze z pliku");
        fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("Plik klucza ElGamal", "*.elgamalKey"));
        File file = fileChooser.showOpenDialog(new Stage());
        if (file != null) {
            try {
                String[] keys = new String(Files.readAllBytes(file.toPath())).split("\n");
                if (keys.length >= 4) {
                    key1Field.setText(keys[0].trim()); // g
                    key2Field.setText(keys[1].trim()); // h
                    key3Field.setText(keys[2].trim()); // a
                    modNField.setText(keys[3].trim()); // p (MOD N)
                    loadKeysField.setText(file.getAbsolutePath());
                } else {
                    showAlert("Błąd", "Plik kluczy musi zawierać dokładnie 4 klucze w formacie hex (g, h, a, p)!");
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
        fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("Plik klucza ElGamal", "*.elgamalKey"));
        File file = fileChooser.showSaveDialog(new Stage());
        if (file != null) {
            try {
                String keys = key1Field.getText() + "\n" + key2Field.getText() + "\n" + key3Field.getText() + "\n" + modNField.getText();
                write(file.toPath(), keys.getBytes());
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
                plaintextArea.setText("Wczytano plik: " + file.getName() + "\nRozmiar: " + plaintextBytes.length + " bajtów");
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
                ciphertextArea.setText("Wczytano plik: " + file.getName() + "\nRozmiar: " + ciphertextBytes.length + " bajtów");
                loadCiphertextField.setText(file.getAbsolutePath());
            } catch (IOException e) {
                showAlert("Błąd", "Problem z wczytaniem pliku: " + e.getMessage());
            }
        }
    }

    @FXML
    private void encrypt() {
        if (elGamal == null) {
            showAlert("Błąd", "Najpierw wygeneruj klucze!");
            return;
        }
        byte[] input;
        if (fileRadio.isSelected()) {
            if (plaintextBytes == null || plaintextBytes.length == 0) {
                showAlert("Błąd", "Wybrałeś szyfrowanie z pliku! Najpierw wczytaj plik z tekstem jawnym.");
                return;
            }
            input = plaintextBytes;
        } else {
            if (plaintextArea.getText().isEmpty()) {
                showAlert("Błąd", "W trybie okna musisz wpisać tekst jawny w polu tekstowym!");
                return;
            }
            input = plaintextArea.getText().getBytes();
        }

        // Szyfrowanie bloku po bloku z ustaloną wartością bloku (256 bajtów)
        int blockSize = 256; // Założenie, dostosuj, jeśli potrzebne
        byte[] paddedInput = data.padInput(input);
        int blockCount = paddedInput.length / blockSize;
        BigInteger[][] ciphertexts = new BigInteger[blockCount][2];
        for (int i = 0; i < blockCount; i++) {
            byte[] block = new byte[blockSize];
            System.arraycopy(paddedInput, i * blockSize, block, 0, blockSize);
            ciphertexts[i] = elGamal.encryptBlock(block);
        }

        // Serializacja szyfrogramu do tekstu (dla trybu okna) lub bajtów (dla pliku)
        if (fileRadio.isSelected()) {
            ciphertextBytes = data.serializeCiphertexts(ciphertexts);
            ciphertextArea.setText("Zaszyfrowano dane.\nRozmiar szyfrogramu: " + ciphertextBytes.length + " bajtów");
        } else {
            StringBuilder result = new StringBuilder();
            for (BigInteger[] ciphertext : ciphertexts) {
                result.append(ciphertext[0].toString(16)).append("\n");
                result.append(ciphertext[1].toString(16)).append("\n");
            }
            ciphertextArea.setText(result.toString());
        }
    }

    @FXML
    private void decrypt() {
        if (elGamal == null) {
            showAlert("Błąd", "Najpierw wygeneruj klucze!");
            return;
        }
        try {
            byte[] input;
            if (fileRadio.isSelected()) {
                if (ciphertextBytes == null || ciphertextBytes.length == 0) {
                    showAlert("Błąd", "Wybrałeś deszyfrowanie z pliku! Najpierw wczytaj plik z szyfrogramem.");
                    return;
                }
                input = ciphertextBytes;
            } else {
                if (ciphertextArea.getText().isEmpty()) {
                    showAlert("Błąd", "W trybie okna musisz wpisać szyfrogram w polu tekstowym!");
                    return;
                }
                String[] lines = ciphertextArea.getText().split("\n");
                BigInteger[][] ciphertexts = new BigInteger[lines.length / 2][2];
                for (int i = 0, j = 0; i < lines.length; i += 2, j++) {
                    ciphertexts[j][0] = new BigInteger(lines[i], 16);
                    ciphertexts[j][1] = new BigInteger(lines[i + 1], 16);
                }
                input = data.serializeCiphertexts(ciphertexts);
            }

            // Deszyfrowanie z ustaloną wartością bloku (256 bajtów)
            int blockSize = 256; // Założenie, dostosuj, jeśli potrzebne
            BigInteger[][] ciphertexts = data.deserializeCiphertexts(input);
            byte[] decrypted = new byte[ciphertexts.length * blockSize];
            for (int i = 0; i < ciphertexts.length; i++) {
                byte[] block = elGamal.decryptBlock(ciphertexts[i][0], ciphertexts[i][1]);
                System.arraycopy(block, 0, decrypted, i * blockSize, blockSize);
            }
            decrypted = data.unpadOutput(decrypted);
            plaintextBytes = decrypted;

            if (fileRadio.isSelected()) {
                plaintextArea.setText("Odszyfrowano dane.\nRozmiar tekstu jawnego: " + plaintextBytes.length + " bajtów");
            } else {
                plaintextArea.setText(new String(plaintextBytes));
            }
        } catch (NumberFormatException e) {
            showAlert("Błąd", "Błąd deszyfrowania: " + e.getMessage());
        }
    }

    @FXML
    private void savePlaintext() {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Zapisz plik z tekstem jawnym");
        File file = fileChooser.showSaveDialog(new Stage());
        if (file != null) {
            try {
                byte[] dataToWrite = (plaintextBytes == null) ? plaintextArea.getText().getBytes() : plaintextBytes;
                Files.write(file.toPath(), dataToWrite);
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
                byte[] dataToWrite;
                if (fileRadio.isSelected()) {
                    if (ciphertextBytes == null || ciphertextBytes.length == 0) {
                        showAlert("Błąd", "Brak szyfrogramu do zapisania! Najpierw wczytaj lub zaszyfruj dane.");
                        return;
                    }
                    dataToWrite = ciphertextBytes;
                } else {
                    String hexText = ciphertextArea.getText();
                    String[] lines = hexText.split("\n");
                    dataToWrite = new byte[lines.length];
                    for (int i = 0; i < lines.length; i++) {
                        dataToWrite[i] = (byte) Integer.parseInt(lines[i], 16);
                    }
                }
                Files.write(file.toPath(), dataToWrite);
                saveCiphertextField.setText(file.getAbsolutePath());
            } catch (NumberFormatException e) {
                showAlert("Błąd", "Nieprawidłowy format szyfrogramu w oknie!");
            } catch (IOException e) {
                showAlert("Błąd", "Problem z zapisem pliku: " + e.getMessage());
            }
        }
    }

    @FXML
    private void clearPlainTextArea() {
        plaintextArea.clear();
        plaintextBytes = null;
        loadPlaintextField.clear();
    }

    @FXML
    private void clearCipherTextAreas() {
        ciphertextArea.clear();
        ciphertextBytes = null;
        loadCiphertextField.clear();
    }

    private void showAlert(String title, String message) {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
    }

    private void showInfoAlert(String title, String message) {
        Alert alert = new Alert(Alert.AlertType.INFORMATION);
        alert.setTitle(title);
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.show();
    }
}