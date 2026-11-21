package com.frontend.controller;

import java.io.File;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BooleanSupplier;

import com.backend.config.AppConfig;
import com.backend.model.Item;
import com.backend.model.ItemType;
import com.backend.model.Result;
import com.backend.service.CsvReadException;
import com.backend.service.CsvReader;
import com.backend.service.CsvResult;
import com.backend.service.Orchestrator;
import com.backend.service.SequentialScanner;
import com.backend.service.VirusTotalChecker;

import javafx.application.Platform;
import javafx.beans.property.SimpleStringProperty;
import javafx.concurrent.Task;
import javafx.fxml.FXML;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.ProgressBar;
import javafx.scene.control.TableCell;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.Tooltip;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;

/**
 * Controller of the Batch Scan tab (BatchScan.fxml).
 * It only reads from the screen, asks the backend for an analysis, and shows the result.
 * It contains NO detection rules.
 */
public class BatchScanController {

    /** One row of the table. */
    public record Row(int num, String type, String content, String status,
                      String level, String duration, String notes) {
    }

    /** What the analysis returns besides the rows. */
    private record Outcome(List<String> warnings, String fileError) {
    }

    /** Called every time one item has been evaluated. */
    private interface RowListener {
        void onRow(int done, int total, Row row);
    }

    // ---- Elements of BatchScan.fxml (names must match the fx:id values) ----
    @FXML private Label resultCountLabel;
    @FXML private Label fileInfoLabel;
    @FXML private Button loadCsvButton;
    @FXML private Button clearResultsButton;
    @FXML private TableView<Row> resultsTable;
    @FXML private TableColumn<Row, String> numberColumn;
    @FXML private TableColumn<Row, String> typeColumn;
    @FXML private TableColumn<Row, String> inputColumn;
    @FXML private TableColumn<Row, String> statusColumn;
    @FXML private TableColumn<Row, String> riskColumn;
    @FXML private VBox detailsEmptyState;
    @FXML private GridPane detailsGrid;
    @FXML private Label detailTypeLabel;
    @FXML private Label detailStatusLabel;
    @FXML private Label detailRiskLabel;
    @FXML private Label detailDurationLabel;
    @FXML private Label detailInputLabel;
    @FXML private Label detailNotesLabel;
    @FXML private ProgressBar progressBar;
    @FXML private Label progressLabel;
    @FXML private Label progressCountLabel;
    @FXML private Button cancelButton;

    private volatile boolean cancelled;

    // ------------------------------------------------------------------
    // Setup: runs once, when BatchScan.fxml is loaded
    // ------------------------------------------------------------------
    @FXML
    public void initialize() {
        numberColumn.setCellValueFactory(c -> new SimpleStringProperty(String.valueOf(c.getValue().num())));
        typeColumn.setCellValueFactory(c -> new SimpleStringProperty(c.getValue().type()));
        inputColumn.setCellValueFactory(c -> new SimpleStringProperty(c.getValue().content()));
        statusColumn.setCellValueFactory(c -> new SimpleStringProperty(c.getValue().status()));
        riskColumn.setCellValueFactory(c -> new SimpleStringProperty(c.getValue().level()));

        // RISK column: bold coloured text, same colours as Single Scan
        riskColumn.setCellFactory(col -> new TableCell<Row, String>() {
            @Override
            protected void updateItem(String item, boolean empty) {
                super.updateItem(item, empty);
                getStyleClass().removeAll("risk-low", "risk-medium", "risk-high", "risk-unknown");
                if (empty || item == null) {
                    setText(null);
                } else {
                    setText(item);
                    getStyleClass().add(riskClass(item));
                }
            }
        });

        // Clicking a row shows its details
        resultsTable.getSelectionModel().selectedItemProperty()
                .addListener((obs, oldRow, row) -> showDetails(row));

        resetScreen();
    }

    // ------------------------------------------------------------------
    // Buttons
    // ------------------------------------------------------------------
    @FXML
    private void handleLoadCsv() {
        FileChooser chooser = new FileChooser();
        chooser.setTitle("Choose a CSV file");
        chooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("CSV files", "*.csv"));
        File file = chooser.showOpenDialog(loadCsvButton.getScene().getWindow());
        if (file == null) {
            return; // the user closed the window: nothing changes
        }
        fileInfoLabel.setText(file.getName());
        startAnalysis(file.toPath());
    }

    @FXML
    private void handleClearResults() {
        resetScreen();
    }

    @FXML
    private void handleCancel() {
        cancelled = true;
        cancelButton.setDisable(true);
        progressLabel.setText("Cancelling...");
    }

    // ------------------------------------------------------------------
    // The analysis runs in a background thread, so the window never freezes
    // ------------------------------------------------------------------
    private void startAnalysis(Path path) {
        resultsTable.getItems().clear();
        showDetails(null);
        resultCountLabel.setText("0 items");
        progressCountLabel.setText("0 of 0 evaluated");
        progressLabel.setText("Analyzing...");
        cancelled = false;
        setRunning(true);

        Task<Outcome> task = new Task<>() {
            @Override
            protected Outcome call() {
                updateProgress(0, 1);
                return analyzeFile(path, (done, total, row) -> {
                    updateProgress(done, total);
                    Platform.runLater(() -> {
                        if (cancelled) {
                            return;
                        }
                        resultsTable.getItems().add(row);
                        resultCountLabel.setText(resultsTable.getItems().size() + " items");
                        progressCountLabel.setText(done + " of " + total + " evaluated");
                    });
                }, () -> cancelled);
            }
        };

        progressBar.progressProperty().bind(task.progressProperty());

        task.setOnSucceeded(e -> {
            progressBar.progressProperty().unbind();
            finish(task.getValue());
        });
        task.setOnFailed(e -> {
            progressBar.progressProperty().unbind();
            progressBar.setProgress(0);
            progressLabel.setText("Failed");
            showAlert(Alert.AlertType.ERROR, "Unexpected error", "Unexpected error while analyzing the file.");
            setRunning(false);
        });

        Thread thread = new Thread(task);
        thread.setName("ThreatGuard-BatchScan");
        thread.setDaemon(true);
        thread.start();
    }

    /** Shows the final result of a run. */
    private void finish(Outcome outcome) {
        int count = resultsTable.getItems().size();
        List<String> warnings = outcome.warnings();

        if (outcome.fileError() != null) {
            progressBar.setProgress(0);
            progressLabel.setText("Failed");
            showAlert(Alert.AlertType.ERROR, "File error", outcome.fileError());
        } else if (cancelled) {
            progressLabel.setText("Cancelled");
        } else {
            progressBar.setProgress(count == 0 ? 0 : 1);
            if (warnings.isEmpty()) {
                progressLabel.setText("Done");
            } else {
                progressLabel.setText("Done - " + warnings.size() + " line(s) skipped");
                showAlert(Alert.AlertType.WARNING,
                        warnings.size() + " line(s) of the CSV were skipped", skippedText(warnings));
            }
        }
        setRunning(false);
    }

    // ------------------------------------------------------------------
    // Small helpers for the screen
    // ------------------------------------------------------------------

    /** Back to the empty "Ready" state. */
    private void resetScreen() {
        resultsTable.getItems().clear();
        fileInfoLabel.setText("No file loaded");
        resultCountLabel.setText("0 items");
        progressBar.progressProperty().unbind();
        progressBar.setProgress(0);
        progressLabel.setText("Ready");
        progressCountLabel.setText("0 of 0 evaluated");
        showDetails(null);
        setRunning(false);
    }

    private void setRunning(boolean running) {
        loadCsvButton.setDisable(running);
        clearResultsButton.setDisable(running);
        cancelButton.setDisable(!running);
    }

    /** Fills the Details panel; null shows the "select a row" message. */
    private void showDetails(Row row) {
        boolean hasRow = row != null;
        detailsGrid.setVisible(hasRow);
        detailsGrid.setManaged(hasRow);
        detailsEmptyState.setVisible(!hasRow);
        detailsEmptyState.setManaged(!hasRow);
        if (!hasRow) {
            return;
        }
        detailTypeLabel.setText(row.type());
        detailStatusLabel.setText(row.status());
        detailRiskLabel.setText(row.level());
        detailRiskLabel.getStyleClass().removeAll("risk-low", "risk-medium", "risk-high", "risk-unknown");
        detailRiskLabel.getStyleClass().add(riskClass(row.level()));
        detailDurationLabel.setText(row.duration());
        detailInputLabel.setText(row.content());
        detailInputLabel.setTooltip(new Tooltip(row.content()));
        detailNotesLabel.setText(row.notes());
        Tooltip notes = new Tooltip(row.notes());
        notes.setWrapText(true);
        notes.setMaxWidth(560);
        detailNotesLabel.setTooltip(notes);
    }

    private static String riskClass(String level) {
        return switch (level) {
            case "Low" -> "risk-low";
            case "Medium" -> "risk-medium";
            case "High" -> "risk-high";
            default -> "risk-unknown"; // Not Verified and anything unexpected: never shown as safe
        };
    }

    private static String skippedText(List<String> warnings) {
        int max = 10;
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(max, warnings.size()); i++) {
            sb.append(warnings.get(i)).append('\n');
        }
        if (warnings.size() > max) {
            sb.append("... and ").append(warnings.size() - max).append(" more");
        }
        return sb.toString().trim();
    }

    private void showAlert(Alert.AlertType type, String header, String text) {
        Alert alert = new Alert(type);
        alert.setTitle("ThreatGuard");
        alert.setHeaderText(header);
        alert.setContentText(text);
        if (loadCsvButton.getScene() != null) {
            alert.initOwner(loadCsvButton.getScene().getWindow());
        }
        alert.show();
    }

    // ==================================================================
    // REAL BACKEND INTEGRATION
    // CSV parsing and detection are delegated to the shared backend.
    // Each item is evaluated on this Task's background thread.
    // ==================================================================
    private Outcome analyzeFile(Path path, RowListener listener, BooleanSupplier isCancelled) {
        List<String> warnings = new ArrayList<>();
        final CsvResult parsed;
        try {
            parsed = new CsvReader().result(path);
        } catch (CsvReadException e) {
            return new Outcome(warnings, e.getMessage());
        }

        for (var error : parsed.errors()) {
            warnings.add(error.toString());
        }

        if (parsed.items().isEmpty()) {
            return new Outcome(warnings, "No valid row found in the CSV file");
        }

        AppConfig config = AppConfig.load(Path.of("config.properties"));
        SequentialScanner scanner = new SequentialScanner(
                new Orchestrator(new VirusTotalChecker(config)));

        int total = parsed.items().size();
        int done = 0;
        for (Item item : parsed.items()) {
            if (isCancelled.getAsBoolean() || Thread.currentThread().isInterrupted()) {
                break;
            }

            Result result = scanner.evaluate(item);
            done++;

            String notes = result.reasonText();
            if (!result.threatTypes().isEmpty()) {
                notes += " | Threat indicators: " + String.join(", ", result.threatTypes());
            }

            Row row = new Row(
                    done,
                    item.type() == ItemType.URL ? "URL" : "MESSAGE",
                    item.content(),
                    result.status().label(),
                    result.riskLevel().label(),
                    result.durationMs() + " ms",
                    notes);

            listener.onRow(done, total, row);
        }

        return new Outcome(warnings, null);
    }
}
