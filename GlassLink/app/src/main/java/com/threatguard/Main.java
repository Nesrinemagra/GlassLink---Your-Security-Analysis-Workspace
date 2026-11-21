package com.threatguard;

import java.io.IOException;

import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.geometry.Rectangle2D;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Screen;
import javafx.stage.Stage;
import javafx.stage.StageStyle;
import javafx.scene.image.Image;

public class Main extends Application {

    private static final double MIN_WIDTH = 900;
    private static final double MIN_HEIGHT = 560;

    @Override
    public void start(Stage stage) throws IOException {
        // 1. Load the main layout
        FXMLLoader loader = new FXMLLoader(
                Main.class.getResource("/com/threatguard/view/Dashboard.fxml"));
        // reads the FXML and creates all the buttons and layouts. It returns the top
        // element as root
        Parent root = loader.load();

        // 2. Usable screen area (without the Windows taskbar)
        // we use getVisualBounds() instaed ofgetBounds() so the window never hides
        // behind the taskbar.
        Rectangle2D screen = Screen.getPrimary().getVisualBounds();

        // 3. Start size: ~80% width, ~90% height, never bigger than the screen
        double width = Math.min(screen.getWidth(), Math.max(MIN_WIDTH, screen.getWidth() * 0.80));
        double height = Math.min(screen.getHeight(), Math.max(MIN_HEIGHT, screen.getHeight() * 0.90));

        Scene scene = new Scene(root, width, height);

        // 4. Normal Windows title bar: minimize / maximize / close
        stage.initStyle(StageStyle.DECORATED);
        stage.setTitle("GlassLink");
        stage.setScene(scene);

        // Set GlassLink application icon
        Image appIcon = new Image(
                Main.class.getResourceAsStream(
                        "/com/threatguard/images/glasslink_logo_extracted.png"));

        stage.getIcons().add(appIcon);

        // 5. Center the window
        stage.setX(screen.getMinX() + (screen.getWidth() - width) / 2);
        stage.setY(screen.getMinY() + (screen.getHeight() - height) / 2);

        stage.show();

        // 6. Lock the minimum size to the content size (this is the "no scrolling"
        // part)
        double extraWidth = stage.getWidth() - scene.getWidth();
        double extraHeight = stage.getHeight() - scene.getHeight();
        stage.setMinWidth(Math.min(Math.max(MIN_WIDTH, root.minWidth(-1) + extraWidth), screen.getWidth()));
        stage.setMinHeight(Math.min(root.minHeight(-1) + extraHeight, screen.getHeight()));
    }

    public static void main(String[] args) {
        launch(args);
    }
}