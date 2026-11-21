
package com.frontend.controller;

import java.util.List;
import java.nio.file.Path;

import com.backend.config.AppConfig;
import com.backend.model.Item;
import com.backend.model.ItemType;
import com.backend.model.Result;
import com.backend.model.Status;
import com.backend.service.Orchestrator;
import com.backend.service.SequentialScanner;
import com.backend.service.VirusTotalChecker;

import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;

public class singlescanController {

    
    
    
    

    @FXML
    private TextArea inputArea;

    @FXML
    private ComboBox<String> typeCombo;

    @FXML
    private Button checkButton;

    @FXML
    private Button clearButton;

    @FXML
    private StackPane resultCard;

    @FXML
    private VBox emptyState;

    @FXML
    private VBox resultContent;

    @FXML
    private Label inputTypeLabel;

    @FXML
    private Label verificationLabel;

    @FXML
    private Label riskBadge;

    @FXML
    private VBox reasonsBox;

    @FXML
    private Label durationLabel;

    
    
    
    

    private record ScanResult(
            String inputType,
            String risk,
            String status,
            boolean verified,
            List<String> reasons,
            String duration) {
    }

    
    
    

    
    private Task<ScanResult> currentTask;

    
    private Label emptyMessage;

    
    
    
    

    @FXML
    public void initialize() {

        
        typeCombo.getItems().addAll(
                "Auto Detect",
                "URL",
                "Message");

        
        typeCombo.getSelectionModel().selectFirst();

        
        emptyMessage = new Label(
                "Please enter a URL or a message.");

        emptyMessage.setStyle(
                "-fx-text-fill: #D13438;");

        
        VBox parent = (VBox) inputArea.getParent();

        int inputIndex = parent.getChildren().indexOf(inputArea);

        parent.getChildren().add(
                inputIndex + 1,
                emptyMessage);

        hideEmptyMessage();

        
        inputArea.textProperty().addListener(
                (observable, oldValue, newValue) -> {

                    if (newValue != null && !newValue.trim().isEmpty()) {
                        hideEmptyMessage();
                    }
                });

        
        showResult(false);

        
        inputTypeLabel.setText("Not scanned");
        applyStatus("Not Verified");
        riskBadge.setText("UNKNOWN");
        durationLabel.setText("Not scanned");
    }

    
    
    
    

    @FXML
    private void onCheck() {

        
        if (currentTask != null && currentTask.isRunning()) {
            return;
        }

        
        String text = inputArea.getText();

        if (text == null) {
            text = "";
        }

        text = text.trim();

        
        if (text.isEmpty()) {

            emptyMessage.setVisible(true);
            emptyMessage.setManaged(true);

            inputArea.requestFocus();

            return;
        }

        
        String selectedType = typeCombo.getValue();

        if (selectedType == null) {
            selectedType = "Auto Detect";
        }

        
        final String scanText = text;
        final String scanType = selectedType;

        
        Task<ScanResult> task = new Task<>() {

            @Override
            protected ScanResult call() throws Exception {

                
                return runScan(scanText, scanType);
            }
        };

        currentTask = task;

        
        checkButton.setDisable(true);
        checkButton.setText("Checking…");

        hideEmptyMessage();

        
        
        

        task.setOnSucceeded(event -> {

            
            if (currentTask != task) {
                return;
            }

            currentTask = null;

            restoreCheckButton();

            ScanResult result = task.getValue();

            if (result == null) {

                showError(
                        scanType,
                        "The backend returned an empty result.");

                return;
            }

            showResultData(result);
        });

        
        
        

        task.setOnFailed(event -> {

            if (currentTask != task) {
                return;
            }

            currentTask = null;

            restoreCheckButton();

            Throwable error = task.getException();

            String message = error == null
                    ? "An unknown scanning error occurred."
                    : error.getMessage();

            showError(scanType, message);
        });

        
        
        

        task.setOnCancelled(event -> {

            if (currentTask == task) {

                currentTask = null;

                restoreCheckButton();
            }
        });

        
        Thread scanThread = new Thread(task);

        scanThread.setName("ThreatGuard-SingleScan");

        scanThread.setDaemon(true);

        scanThread.start();
    }

    
    
    
    

    @FXML
    private void onClear() {

        
        if (currentTask != null) {

            Task<ScanResult> taskToCancel = currentTask;

            currentTask = null;

            taskToCancel.cancel();
        }

        
        restoreCheckButton();

        
        inputArea.clear();

        
        typeCombo.getSelectionModel().selectFirst();

        
        hideEmptyMessage();

        
        reasonsBox.getChildren().clear();

        
        inputTypeLabel.setText("Not scanned");

        applyStatus("Not Verified");

        riskBadge.setText("UNKNOWN");
        durationLabel.setText("Not scanned");



        
        showResult(false);
    }

    
    
    

    private void restoreCheckButton() {

        checkButton.setDisable(false);

        checkButton.setText("Check");
    }

    
    
    

    private void hideEmptyMessage() {

        emptyMessage.setVisible(false);

        emptyMessage.setManaged(false);
    }

    
    
    
    
    
    
    

    private ScanResult runScan(
            String text,
            String selectedType) throws Exception {

        ItemType itemType = resolveType(text, selectedType);
        Item item = Item.create(itemType, text);

        AppConfig config = AppConfig.load(Path.of("config.properties"));
        SequentialScanner scanner = new SequentialScanner(
                new Orchestrator(new VirusTotalChecker(config)));

        Result result = scanner.evaluate(item);

        boolean externallyVerified = itemType == ItemType.URL
                && (result.status() == Status.SAFE || result.status() == Status.DANGER);

        String duration = result.durationMs() + " ms";

        return new ScanResult(
                itemType == ItemType.URL ? "URL" : "Message",
                result.riskLevel().name(),
                result.status().label(),
                externallyVerified,
                result.reasons(),
                duration);
    }

    private ItemType resolveType(String text, String selectedType) {
        if ("URL".equalsIgnoreCase(selectedType)) {
            return ItemType.URL;
        }
        if ("Message".equalsIgnoreCase(selectedType)) {
            return ItemType.MESSAGE;
        }

        
        String candidate = text.trim();
        return candidate.matches("(?i)^https?://\\S+$")
                ? ItemType.URL
                : ItemType.MESSAGE;
    }

    
    
    

    private void showResultData(ScanResult result) {

        
        inputTypeLabel.setText(
                result.inputType() == null
                        ? "Unknown"
                        : result.inputType());

        
        setRiskAndStatus(
                result.risk(),
                result.status(),
                result.verified());

        
        reasonsBox.getChildren().clear();

        
        if (result.reasons() == null || result.reasons().isEmpty()) {

            addReason("No detection reasons provided.");

        } else {

            for (String reason : result.reasons()) {

                if (reason != null && !reason.isBlank()) {
                    addReason(reason);
                }
            }
        }

        
        durationLabel.setText(
                result.duration() == null || result.duration().isBlank()
                        ? "—"
                        : result.duration());

        
        showResult(true);
    }

    
    
    

    private void showError(
            String selectedType,
            String errorMessage) {

        inputTypeLabel.setText(selectedType);

        
        setRiskAndStatus("UNKNOWN", "Error", false);

        reasonsBox.getChildren().clear();

        addReason("The scan could not be completed.");

        durationLabel.setText("—");

        showResult(true);
    }

    
    
    

    private void setRiskAndStatus(
            String risk,
            String status,
            boolean verified) {

        String finalRisk = risk == null
                ? "UNKNOWN"
                : risk.trim().toUpperCase();

        
        if (!List.of(
                "HIGH",
                "MEDIUM",
                "LOW",
                "UNKNOWN").contains(finalRisk)) {

            finalRisk = "UNKNOWN";

            verified = false;
        }

        
        

        
        riskBadge.setText(finalRisk.equals("UNKNOWN") ? "NOT VERIFIED" : finalRisk);

        
        riskBadge.getStyleClass().removeAll(
                "risk-high",
                "risk-medium",
                "risk-low",
                "risk-unknown");

        
        riskBadge.getStyleClass().add(
                "risk-" + finalRisk.toLowerCase());

        
        
        applyStatus(status);
    }

    
    private void applyStatus(String status) {

        String text = (status == null || status.isBlank())
                ? "Not Verified"
                : status.trim();

        verificationLabel.setText(text);

        verificationLabel.getStyleClass().removeAll(
                "status-safe",
                "status-danger",
                "status-suspect",
                "status-low-risk",
                "status-unverified",
                "status-error");

        String styleClass = switch (text) {
            case "Safe" -> "status-safe";
            case "Danger" -> "status-danger";
            case "Suspect" -> "status-suspect";
            case "Low Risk" -> "status-low-risk";
            case "Error" -> "status-error";
            default -> "status-unverified"; 
        };

        verificationLabel.getStyleClass().add(styleClass);
    }

    
    
    

    private void addReason(String reason) {

        Label reasonLabel = new Label(
                "• " + reason);

        reasonLabel.getStyleClass().add(
                "reason-label");

        reasonLabel.setWrapText(true);

        reasonsBox.getChildren().add(reasonLabel);
    }

    
    
    

    private void showResult(boolean show) {

        
        resultContent.setVisible(show);

        resultContent.setManaged(show);

        
        emptyState.setVisible(!show);

        emptyState.setManaged(!show);
    }
}
