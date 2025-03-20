module org.example.des {
    requires javafx.controls;
    requires javafx.fxml;


    opens org.example.des to javafx.fxml;
    exports org.example.des;
}