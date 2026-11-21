package com.backend.ai;

import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Locale;
import java.util.Properties;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

   
                                              
  
                                                                                
                                                                                
                                                                              
                                          
   
public final class AiConfig {

    private static final String DEFAULT_PROVIDER = "auto";
    private static final String DEFAULT_OPENAI_BASE_URL = "https://api.groq.com/openai/v1";
    private static final String DEFAULT_OPENAI_MODEL = "openai/gpt-oss-20b";

    private final String baseUrl;
    private final String password;
    private final String opencodeModel;
    private final String provider;
    private final String providerBaseUrl;
    private final String providerKey;
    private final String providerModel;
    private final Duration timeout;

    public AiConfig(String baseUrl, String password, Duration timeout) {
        this(baseUrl, password, timeout, "");
    }

    public AiConfig(String baseUrl, String password, Duration timeout, String opencodeModel) {
        this(baseUrl, password, timeout, opencodeModel, DEFAULT_PROVIDER,
                DEFAULT_OPENAI_BASE_URL, "", DEFAULT_OPENAI_MODEL);
    }

    public AiConfig(String baseUrl, String password, Duration timeout, String opencodeModel,
            String provider, String providerBaseUrl, String providerKey, String providerModel) {
        this.baseUrl = baseUrl == null ? "" : baseUrl.trim();
        this.password = password == null ? "" : password.trim();
        this.opencodeModel = opencodeModel == null ? "" : opencodeModel.trim();
        this.provider = normalizeProvider(provider);
        this.providerBaseUrl = providerBaseUrl == null || providerBaseUrl.isBlank()
                ? DEFAULT_OPENAI_BASE_URL : providerBaseUrl.trim();
        this.providerKey = cleanKey(providerKey);
        this.providerModel = providerModel == null || providerModel.isBlank()
                ? DEFAULT_OPENAI_MODEL : providerModel.trim();
        this.timeout = timeout == null ? Duration.ofSeconds(60) : timeout;
    }

    public String baseUrl() {
        return baseUrl;
    }

    public String password() {
        return password;
    }

    public Duration timeout() {
        return timeout;
    }

                                                                                      
    public String model() {
        return opencodeModel;
    }

                                                                        
    public String provider() {
        return provider;
    }

    public String providerBaseUrl() {
        return providerBaseUrl;
    }

    public String providerKey() {
        return providerKey;
    }

    public String providerModel() {
        return providerModel;
    }

    public boolean isConfigured() {
        return isOpenCodeConfigured();
    }

    public boolean isOpenCodeConfigured() {
        return !baseUrl.isEmpty() && !password.isEmpty();
    }

    public boolean isOpenAiCompatibleConfigured() {
        return !providerBaseUrl.isEmpty() && !providerKey.isEmpty() && !providerModel.isEmpty();
    }

    public static AiConfig load(Path configFile) throws AiGenerationException {
        Properties props = new Properties();
        if (configFile != null && Files.isRegularFile(configFile)) {
            try (Reader reader = Files.newBufferedReader(configFile, StandardCharsets.UTF_8)) {
                props.load(reader);
            } catch (IOException | IllegalArgumentException e) {
                
                System.err.println("Could not read " + configFile + " for AI settings: " + e.getMessage());
            }
        }

        Path serviceFile = resolveServiceFile(props);
        String url = envOrProp("OPENCODE_API_URL", props, "ai.opencode.url", "");
        String password = envOrProp("OPENCODE_API_PASSWORD", props, "ai.opencode.password", "");

        if (Files.isRegularFile(serviceFile)) {
            JsonObject registration;
            try {
                String json = Files.readString(serviceFile, StandardCharsets.UTF_8);
                registration = JsonParser.parseString(json).getAsJsonObject();
            } catch (IOException | RuntimeException e) {
                throw new AiGenerationException(
                        "The OpenCode service registration could not be read. Start OpenCode and try again.", e);
            }
            if (url.isEmpty()) {
                url = readString(registration, "url");
            }
            if (password.isEmpty()) {
                password = readString(registration, "password");
            }
        }

        String opencodeModel = envOrProp("OPENCODE_MODEL", props, "ai.opencode.model", "");
        String provider = firstNonBlank(
                System.getenv("AI_PROVIDER"),
                props.getProperty("ai.provider", ""));
        String providerBaseUrl = firstNonBlank(
                System.getenv("GROQ_BASE_URL"),
                System.getenv("AI_PROVIDER_BASE_URL"),
                props.getProperty("ai.openai.base.url", ""));
        String providerKey = firstNonBlank(
                System.getenv("GROQ_API_KEY"),
                System.getenv("AI_API_KEY"),
                props.getProperty("ai.openai.api.key", ""));
        String providerModel = firstNonBlank(
                System.getenv("GROQ_MODEL"),
                System.getenv("AI_PROVIDER_MODEL"),
                props.getProperty("ai.openai.model", ""));
        int seconds = parseInt(envOrProp("AI_TIMEOUT_SECONDS", props, "ai.timeout.seconds", "60"));
        if (seconds <= 0) {
            seconds = 60;
        }

        return new AiConfig(url, password, Duration.ofSeconds(seconds), opencodeModel,
                provider, providerBaseUrl, providerKey, providerModel);
    }

    private static Path resolveServiceFile(Properties props) {
        String configured = envOrProp("OPENCODE_SERVICE_FILE", props, "ai.opencode.service-file", "");
        if (!configured.isEmpty()) {
            return Path.of(configured).toAbsolutePath();
        }

        String stateHome = System.getenv("XDG_STATE_HOME");
        Path base = (stateHome == null || stateHome.isBlank())
                ? Path.of(System.getProperty("user.home"), ".local", "state")
                : Path.of(stateHome);
        return base.resolve("opencode").resolve("service.json");
    }

    private static String envOrProp(String envName, Properties props, String propName, String fallback) {
        String fromEnv = System.getenv(envName);
        if (fromEnv != null && !fromEnv.isBlank()) {
            return fromEnv.trim();
        }
        return props.getProperty(propName, fallback).trim();
    }

    private static String firstNonBlank(String... values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value.trim();
            }
        }
        return "";
    }

    private static String normalizeProvider(String value) {
        String provider = value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
        return switch (provider) {
            case "opencode", "openai-compatible", "openai_compatible", "openai", "groq" ->
                    provider.startsWith("openai") || provider.equals("groq") ? "openai-compatible" : provider;
            default -> DEFAULT_PROVIDER;
        };
    }

    private static String cleanKey(String value) {
        String key = value == null ? "" : value.trim();
        String upper = key.toUpperCase(Locale.ROOT);
        if (upper.contains("PASTE_") || upper.contains("YOUR_") || upper.contains("_HERE")
                || upper.equals("CHANGE_ME") || upper.equals("CHANGEME")) {
            return "";
        }
        return key;
    }

    private static int parseInt(String value) {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            return 60;
        }
    }

    private static String readString(JsonObject object, String name) {
        var value = object.get(name);
        return value != null && value.isJsonPrimitive() ? value.getAsString() : "";
    }
}
