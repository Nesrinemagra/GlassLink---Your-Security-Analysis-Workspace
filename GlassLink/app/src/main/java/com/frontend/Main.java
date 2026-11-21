package com.frontend;

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
        
        FXMLLoader loader = new FXMLLoader(
                Main.class.getResource("/com/frontend/view/Dashboard.fxml"));
        
        
        Parent root = loader.load();

        
        
        
        Rectangle2D screen = Screen.getPrimary().getVisualBounds();

        
        double width = Math.min(screen.getWidth(), Math.max(MIN_WIDTH, screen.getWidth() * 0.80));
        double height = Math.min(screen.getHeight(), Math.max(MIN_HEIGHT, screen.getHeight() * 0.90));

        Scene scene = new Scene(root, width, height);

        
        stage.initStyle(StageStyle.DECORATED);
        stage.setTitle("GlassLink");
        stage.setScene(scene);

        
        Image appIcon = new Image(
                Main.class.getResourceAsStream(
                        "/com/frontend/images/glasslink_logo_extracted.png"));

        stage.getIcons().add(appIcon);

        
        stage.setX(screen.getMinX() + (screen.getWidth() - width) / 2);
        stage.setY(screen.getMinY() + (screen.getHeight() - height) / 2);

        stage.show();

        
        
        double extraWidth = stage.getWidth() - scene.getWidth();
        double extraHeight = stage.getHeight() - scene.getHeight();
        stage.setMinWidth(Math.min(Math.max(MIN_WIDTH, root.minWidth(-1) + extraWidth), screen.getWidth()));
        stage.setMinHeight(Math.min(root.minHeight(-1) + extraHeight, screen.getHeight()));
    }

    public static void main(String[] args) {
        launch(args);
    }
}