
package com.threatguard.controller;

import java.util.List;
import java.nio.file.Path;

import com.threatdetector.config.AppConfig;
import com.threatdetector.model.Item;
import com.threatdetector.model.ItemType;
import com.threatdetector.model.Result;
import com.threatdetector.model.Status;
import com.threatdetector.service.Orchestrator;
import com.threatdetector.service.SequentialScanner;
import com.threatdetector.service.VirusTotalChecker;

import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;

public class singlescanController {

    // ==================================================
    // 1. FXML ELEMENTS
    // These fields connect Java to your FXML using fx:id.
    // ==================================================

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

    // ==================================================
    // 2. RESULT MODEL
    // This is the information the backend must return.
    // ==================================================

    private record ScanResult(
            String inputType,
            String risk,
            String status,
            boolean verified,
            List<String> reasons,
            String duration) {
    }

    // ==================================================
    // 3. CONTROLLER STATE
    // ==================================================

    // The task currently running.
    private Task<ScanResult> currentTask;

    // Warning displayed when the input is empty.
    private Label emptyMessage;

    // ==================================================
    // 4. INITIALIZE
    // Runs automatically when the FXML screen loads.
    // ==================================================

    @FXML
    public void initialize() {

        // Fill the ComboBox.
        typeCombo.getItems().addAll(
                "Auto Detect",
                "URL",
                "Message");

        // Select Auto Detect by default.
        typeCombo.getSelectionModel().selectFirst();

        // Create the empty-input warning.
        emptyMessage = new Label(
                "Please enter a URL or a message.");

        emptyMessage.setStyle(
                "-fx-text-fill: #D13438;");

        // Insert the warning immediately after the TextArea.
        VBox parent = (VBox) inputArea.getParent();

        int inputIndex = parent.getChildren().indexOf(inputArea);

        parent.getChildren().add(
                inputIndex + 1,
                emptyMessage);

        hideEmptyMessage();

        // Hide the warning when the user starts typing.
        inputArea.textProperty().addListener(
                (observable, oldValue, newValue) -> {

                    if (newValue != null && !newValue.trim().isEmpty()) {
                        hideEmptyMessage();
                    }
                });

        // Display the initial empty result state.
        showResult(false);

        // Set the initial result labels.
        inputTypeLabel.setText("Not scanned");
        applyStatus("Not Verified");
        riskBadge.setText("UNKNOWN");
        durationLabel.setText("Not scanned");
    }

    // ==================================================
    // 5. CHECK BUTTON
    // Reads the input and starts a background scan.
    // ==================================================

    @FXML
    private void onCheck() {

        // Prevent starting another scan while one is running.
        if (currentTask != null && currentTask.isRunning()) {
            return;
        }

        // Read and clean the input.
        String text = inputArea.getText();

        if (text == null) {
            text = "";
        }

        text = text.trim();

        // Validate that the input is not empty.
        if (text.isEmpty()) {

            emptyMessage.setVisible(true);
            emptyMessage.setManaged(true);

            inputArea.requestFocus();

            return;
        }

        // Read the selected input type.
        String selectedType = typeCombo.getValue();

        if (selectedType == null) {
            selectedType = "Auto Detect";
        }

        // Store the values for the background task.
        final String scanText = text;
        final String scanType = selectedType;

        // Create a JavaFX background task.
        Task<ScanResult> task = new Task<>() {

            @Override
            protected ScanResult call() throws Exception {

                // The backend performs the actual detection.
                return runScan(scanText, scanType);
            }
        };

        currentTask = task;

        // Update the interface while scanning.
        checkButton.setDisable(true);
        checkButton.setText("Checking…");

        hideEmptyMessage();

        // ----------------------------------------------
        // SCAN SUCCESS
        // ----------------------------------------------

        task.setOnSucceeded(event -> {

            // Ignore an old task if Clear was clicked.
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

        // ----------------------------------------------
        // SCAN FAILURE
        // ----------------------------------------------

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

        // ----------------------------------------------
        // SCAN CANCELLED
        // ----------------------------------------------

        task.setOnCancelled(event -> {

            if (currentTask == task) {

                currentTask = null;

                restoreCheckButton();
            }
        });

        // Start the task in a separate thread.
        Thread scanThread = new Thread(task);

        scanThread.setName("ThreatGuard-SingleScan");

        scanThread.setDaemon(true);

        scanThread.start();
    }

    // ==================================================
    // 6. CLEAR BUTTON
    // Resets the screen and cancels an active scan.
    // ==================================================

    @FXML
    private void onClear() {

        // Cancel the current scan if one exists.
        if (currentTask != null) {

            Task<ScanResult> taskToCancel = currentTask;

            currentTask = null;

            taskToCancel.cancel();
        }

        // Restore the Check button.
        restoreCheckButton();

        // Clear the input.
        inputArea.clear();

        // Select Auto Detect again.
        typeCombo.getSelectionModel().selectFirst();

        // Hide the empty-input warning.
        hideEmptyMessage();

        // Remove previous detection reasons.
        reasonsBox.getChildren().clear();

        // Reset result labels.
        inputTypeLabel.setText("Not scanned");

        applyStatus("Not Verified");

        riskBadge.setText("UNKNOWN");
        durationLabel.setText("Not scanned");



        // Display the initial empty state.
        showResult(false);
    }

    // ==================================================
    // 7. RESTORE CHECK BUTTON
    // ==================================================

    private void restoreCheckButton() {

        checkButton.setDisable(false);

        checkButton.setText("Check");
    }

    // ==================================================
    // 8. EMPTY INPUT WARNING
    // ==================================================

    private void hideEmptyMessage() {

        emptyMessage.setVisible(false);

        emptyMessage.setManaged(false);
    }

    // ==================================================
    // 9. BACKEND CONNECTION
    //
    // IMPORTANT:
    // Your teammates are responsible for detection.
    // They should connect their service in this method.
    // ==================================================

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

        // Auto Detect: a URI with an http(s) scheme is treated as a URL.
        String candidate = text.trim();
        return candidate.matches("(?i)^https?://\\S+$")
                ? ItemType.URL
                : ItemType.MESSAGE;
    }

    // ==================================================
    // 10. DISPLAY A SUCCESSFUL RESULT
    // ==================================================

    private void showResultData(ScanResult result) {

        // Display the input type.
        inputTypeLabel.setText(
                result.inputType() == null
                        ? "Unknown"
                        : result.inputType());

        // Update the risk and verification labels.
        setRiskAndStatus(
                result.risk(),
                result.status(),
                result.verified());

        // Remove old reasons.
        reasonsBox.getChildren().clear();

        // Display detection reasons.
        if (result.reasons() == null || result.reasons().isEmpty()) {

            addReason("No detection reasons provided.");

        } else {

            for (String reason : result.reasons()) {

                if (reason != null && !reason.isBlank()) {
                    addReason(reason);
                }
            }
        }

        // Display the scan duration.
        durationLabel.setText(
                result.duration() == null || result.duration().isBlank()
                        ? "—"
                        : result.duration());

        // Display the result.
        showResult(true);
    }

    // ==================================================
    // 11. DISPLAY A SCANNING ERROR
    // ==================================================

    private void showError(
            String selectedType,
            String errorMessage) {

        inputTypeLabel.setText(selectedType);

        // An error must never be presented as a safe result.
        setRiskAndStatus("UNKNOWN", "Error", false);

        reasonsBox.getChildren().clear();

        addReason("The scan could not be completed.");

        durationLabel.setText("—");

        showResult(true);
    }

    // ==================================================
    // 12. UPDATE RISK AND VERIFICATION
    // ==================================================

    private void setRiskAndStatus(
            String risk,
            String status,
            boolean verified) {

        String finalRisk = risk == null
                ? "UNKNOWN"
                : risk.trim().toUpperCase();

        // Accept only the four supported risk levels.
        if (!List.of(
                "HIGH",
                "MEDIUM",
                "LOW",
                "UNKNOWN").contains(finalRisk)) {

            finalRisk = "UNKNOWN";

            verified = false;
        }

        // LOW_RISK is a rule-based message result, not an externally verified SAFE result.
        // Keep the backend's LOW level while the separate status label says Not Verified.

        // Update the risk text.
        riskBadge.setText(finalRisk.equals("UNKNOWN") ? "NOT VERIFIED" : finalRisk);

        // Remove the previous risk style.
        riskBadge.getStyleClass().removeAll(
                "risk-high",
                "risk-medium",
                "risk-low",
                "risk-unknown");

        // Apply the correct risk style.
        riskBadge.getStyleClass().add(
                "risk-" + finalRisk.toLowerCase());

        // Status: same choices as Batch Scan
        // (Safe, Danger, Suspect, Low Risk, Not Verified, Error).
        applyStatus(status);
    }

    // Shows the status text and colours it like its meaning.
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
            default -> "status-unverified"; // Not Verified and anything unexpected
        };

        verificationLabel.getStyleClass().add(styleClass);
    }

    // ==================================================
    // 13. ADD A DETECTION REASON
    // ==================================================

    private void addReason(String reason) {

        Label reasonLabel = new Label(
                "• " + reason);

        reasonLabel.getStyleClass().add(
                "reason-label");

        reasonLabel.setWrapText(true);

        reasonsBox.getChildren().add(reasonLabel);
    }

    // ==================================================
    // 14. SHOW RESULT OR EMPTY STATE
    // ==================================================

    private void showResult(boolean show) {

        // Show the result content.
        resultContent.setVisible(show);

        resultContent.setManaged(show);

        // Show the empty state when there is no result.
        emptyState.setVisible(!show);

        emptyState.setManaged(!show);
    }
}
