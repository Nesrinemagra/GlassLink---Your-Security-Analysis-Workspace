package com.frontend.controller;

import java.nio.file.Path;

import com.backend.config.AppConfig;

import javafx.fxml.FXML;
import javafx.scene.control.Label;
import javafx.scene.paint.Color;
import javafx.scene.shape.Circle;

public class DashboardController {
    @FXML
    private Circle apiStatusDot;

    @FXML
    private Label apiStatusLabel;

    @FXML
    public void initialize() {
        AppConfig config = AppConfig.load(Path.of("config.properties"));
        if (config.hasApiKey()) {
            apiStatusDot.setFill(Color.web("#D69E36"));
            apiStatusLabel.setText("VirusTotal key configured");
        } else {
            apiStatusDot.setFill(Color.web("#D9534F"));
            apiStatusLabel.setText("VirusTotal key not configured");
        }
    }
}
