package com.frontend.controller;

import java.nio.file.Path;

import com.backend.ai.AiAnalysisResult;
import com.backend.ai.AiAnalyzer;
import com.backend.ai.AiConfig;
import com.backend.ai.AiTextGenerators;

import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.scene.layout.StackPane;
import javafx.scene.layout.VBox;

/**
 * Controller of the AI Analysis tab (AIAnalysis.fxml).
 * It mirrors the Single Scan screen and uses only the AI backend.
 */
public class AIAnalysisController {

    @FXML
    private TextArea inputArea;

    @FXML
    private Button analyzeButton;

    @FXML
    private Button clearButton;

    @FXML
    private StackPane resultCard;

    @FXML
    private VBox emptyState;

    @FXML
    private Label emptyTitle;

    @FXML
    private Label emptyText;

    @FXML
    private VBox resultContent;

    @FXML
    private Label aiTypeLabel;

    @FXML
    private Label aiStatusLabel;

    @FXML
    private Label aiRiskBadge;

    @FXML
    private VBox insightsBox;

    private Task<AiAnalysisResult> currentTask;
    private Label emptyMessage;

    @FXML
    public void initialize() {
        emptyMessage = new Label("Please enter a URL or a message.");
        emptyMessage.setStyle("-fx-text-fill: #D13438;");

        VBox parent = (VBox) inputArea.getParent();
        int inputIndex = parent.getChildren().indexOf(inputArea);
        parent.getChildren().add(inputIndex + 1, emptyMessage);
        hideEmptyMessage();

        inputArea.textProperty().addListener((observable, oldValue, newValue) -> {
            if (newValue != null && !newValue.trim().isEmpty()) {
                hideEmptyMessage();
            }
        });

        resetEmptyState();
        showResult(false);

        aiTypeLabel.setText("Not scanned");
        applyStatus("Not Verified");
        applyRisk("UNKNOWN");
    }

    @FXML
    private void onAnalyze() {
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

        final String analysisText = text;

        Task<AiAnalysisResult> task = new Task<>() {
            @Override
            protected AiAnalysisResult call() throws Exception {
                return runAnalysis(analysisText);
            }
        };

        currentTask = task;
        analyzeButton.setDisable(true);
        analyzeButton.setText("Analyzing…");
        hideEmptyMessage();

        showLoading();

        task.setOnSucceeded(event -> {
            if (currentTask != task) {
                return;
            }
            currentTask = null;
            restoreAnalyzeButton();
            resetEmptyState();

            AiAnalysisResult result = task.getValue();
            if (result == null) {
                showError("The AI backend returned an empty result.");
                return;
            }
            showResultData(result);
        });

        task.setOnFailed(event -> {
            if (currentTask != task) {
                return;
            }
            currentTask = null;
            restoreAnalyzeButton();
            resetEmptyState();

            Throwable error = task.getException();
            String message = error == null || error.getMessage() == null || error.getMessage().isBlank()
                    ? "The AI analysis could not be completed."
                    : error.getMessage();
            showError(message);
        });

        task.setOnCancelled(event -> {
            if (currentTask == task) {
                currentTask = null;
                restoreAnalyzeButton();
                resetEmptyState();
                showResult(false);
            }
        });

        Thread thread = new Thread(task);
        thread.setName("ThreatGuard-AIAnalysis");
        thread.setDaemon(true);
        thread.start();
    }

    @FXML
    private void onClear() {
        if (currentTask != null) {
            Task<AiAnalysisResult> taskToCancel = currentTask;
            currentTask = null;
            taskToCancel.cancel();
        }

        restoreAnalyzeButton();
        inputArea.clear();
        hideEmptyMessage();
        insightsBox.getChildren().clear();
        aiTypeLabel.setText("Not scanned");
        applyStatus("Not Verified");
        applyRisk("UNKNOWN");
        resetEmptyState();
        showResult(false);
    }

    private AiAnalysisResult runAnalysis(String text) throws Exception {
        AiConfig config = AiConfig.load(Path.of("config.properties"));
        AiAnalyzer analyzer = new AiAnalyzer(AiTextGenerators.create(config));
        return analyzer.analyze(text, "Auto Detect");
    }

    private void restoreAnalyzeButton() {
        analyzeButton.setDisable(false);
        analyzeButton.setText("Analyze");
    }

    private void hideEmptyMessage() {
        emptyMessage.setVisible(false);
        emptyMessage.setManaged(false);
    }

    private void showLoading() {
        emptyTitle.setText("Analyzing…");
        emptyText.setText("The AI is reviewing this URL or message.");
        showResult(false);
    }

    private void resetEmptyState() {
        emptyTitle.setText("No analysis yet");
        emptyText.setText("Paste something above and click Analyze");
    }

    private void showResultData(AiAnalysisResult result) {
        aiTypeLabel.setText(result.type() == null ? "Unknown" : result.type());
        setRiskAndStatus(result.risk(), result.status());

        insightsBox.getChildren().clear();
        if (result.insights().isEmpty()) {
            addInsight("No specific AI indicators were reported.");
        } else {
            result.insights().forEach(this::addInsight);
        }

        showResult(true);
    }

    private void showError(String errorMessage) {
        aiTypeLabel.setText("Unknown");
        setRiskAndStatus("UNKNOWN", "Error");

        insightsBox.getChildren().clear();
        addInsight(errorMessage == null || errorMessage.isBlank()
                ? "The AI analysis could not be completed."
                : errorMessage);

        showResult(true);
    }

    private void setRiskAndStatus(String risk, String status) {
        applyRisk(risk);
        applyStatus(status);
    }

    private void applyRisk(String risk) {
        String finalRisk = risk == null ? "UNKNOWN" : risk.trim().toUpperCase();
        if (!AiAnalysisResult.ALLOWED_RISKS.contains(finalRisk)) {
            finalRisk = "UNKNOWN";
        }

        aiRiskBadge.setText("UNKNOWN".equals(finalRisk) ? "NOT VERIFIED" : finalRisk);
        aiRiskBadge.getStyleClass().removeAll("risk-high", "risk-medium", "risk-low", "risk-unknown");
        aiRiskBadge.getStyleClass().add("risk-" + finalRisk.toLowerCase());
    }

    private void applyStatus(String status) {
        String text = status == null || status.isBlank() ? "Not Verified" : status.trim();
        aiStatusLabel.setText(text);
        aiStatusLabel.getStyleClass().removeAll(
                "status-safe", "status-danger", "status-suspect",
                "status-low-risk", "status-unverified", "status-error");

        String styleClass = switch (text) {
            case "Safe" -> "status-safe";
            case "Danger" -> "status-danger";
            case "Suspect" -> "status-suspect";
            case "Low Risk" -> "status-low-risk";
            case "Error" -> "status-error";
            default -> "status-unverified";
        };
        aiStatusLabel.getStyleClass().add(styleClass);
    }

    private void addInsight(String insight) {
        Label label = new Label("• " + insight);
        label.getStyleClass().add("reason-label");
        label.setWrapText(true);
        insightsBox.getChildren().add(label);
    }

    private void showResult(boolean show) {
        resultContent.setVisible(show);
        resultContent.setManaged(show);
        emptyState.setVisible(!show);
        emptyState.setManaged(!show);
    }
}
