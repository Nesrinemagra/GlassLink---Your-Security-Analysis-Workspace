package com.backend.config;

import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Properties;

public final class AppConfig {

    public static final String ApiKeyEnv = "VIRUSTOTAL_API_KEY";

    private static final int DefaultTimeout = 5;
    private static final int Default_Retries = 2;

    private final String apiKey;
    private final Duration timeout;
    private final int maxRetries;

    public AppConfig(String apiKey, Duration timeout, int maxRetries) {
        this.apiKey = apiKey == null ? "" : apiKey.trim();
        this.timeout = timeout;
        this.maxRetries = Math.max(0, maxRetries);
    }

    public static AppConfig withKey(String apiKey) {
        return new AppConfig(apiKey, Duration.ofSeconds(DefaultTimeout),
             Default_Retries);
    }

    public static AppConfig load(Path file) {
        Properties props = new Properties(); 
        if (file != null && Files.isRegularFile(file)) {
            try (Reader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
                props.load(reader);
            } catch (IOException | IllegalArgumentException e) {
                System.err.println("Could not read " + file + ", using defaults: " + e.getMessage());
            }
        }

        String key = System.getenv(ApiKeyEnv);
        if (key == null || key.isBlank()) {
            key = props.getProperty("virustotal.api.key", "");
        }
        if (key.trim().equals("PASTE_YOUR_KEY_HERE") || key.trim().equals("PASTE_VIRUSTOTAL_KEY_HERE")) {
            key = "";
        }

        int timeout = readInt(props, "http.timeout.seconds", DefaultTimeout);
        int retries = readInt(props, "max.retries", Default_Retries);

        return new AppConfig(key, Duration.ofSeconds(Math.max(1, timeout)), retries);
    }

    private static int readInt(Properties props, String name, int defaultValue) {
        String value = props.getProperty(name);
        if (value == null || value.isBlank()) {
            return defaultValue;
        }
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            System.err.println("Invalid value for " + name + ": '" + value + "', using " + defaultValue);
            return defaultValue;
        }
    }

    public String apiKey() {
        return apiKey;
    }

    public boolean hasApiKey() {
        return !apiKey.isEmpty();
    }

    public Duration timeout() {
        return timeout;
    }
    public int maxRetries() {
        return maxRetries;
    }
}
