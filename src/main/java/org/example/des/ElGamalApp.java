package org.example.des;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Scene;
import javafx.stage.Stage;

import java.io.IOException;

public class ElGamalApp extends Application {
    @Override
    public void start(Stage stage) throws IOException {
        FXMLLoader fxmlLoader = new FXMLLoader(ElGamalApp.class.getResource("ElGamalApp.fxml"));
        Scene scene = new Scene(fxmlLoader.load(), 650, 440);
        stage.setTitle("ElGamal Szyfrowanie");
        stage.setScene(scene);
        stage.show();
    }

    public static void main(String[] args) {
        launch();
    }
}