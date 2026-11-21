package com.threatdetector.ai;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * The only {@link AiTextGenerator} implementation.
 *
 * Talks to the local OpenCode service instead of an inference API. OpenCode
 * owns the inference credentials and the configured provider/model; this client
 * only sends a prompt to its stateless generation endpoint and authenticates
 * with the local service password. No API key is kept in the UI.
 */
public final class OpenCodeTextGenerator implements AiTextGenerator {

    static final String ENDPOINT = "/api/experimental/generate/text";
    private static final int MAX_ERROR_DETAIL = 180;

    private final URI endpoint;
    private final String authorization;
    private final HttpClient http;
    private final Duration timeout;
    private final String modelProvider;
    private final String modelId;

    public OpenCodeTextGenerator(String baseUrl, String servicePassword, Duration timeout) {
        this(baseUrl, servicePassword, timeout, null);
    }

    public OpenCodeTextGenerator(String baseUrl, String servicePassword, Duration timeout, String model) {
        String base = baseUrl == null ? "" : baseUrl.trim();
        while (base.endsWith("/")) {
            base = base.substring(0, base.length() - 1);
        }
        if (base.isEmpty()) {
            throw new IllegalArgumentException("baseUrl");
        }
        this.endpoint = URI.create(base + ENDPOINT);
        String password = servicePassword == null ? "" : servicePassword;
        this.authorization = "Basic " + Base64.getEncoder().encodeToString(
                ("opencode:" + password).getBytes(StandardCharsets.UTF_8));
        this.timeout = timeout == null ? Duration.ofSeconds(60) : timeout;
        String selected = model == null ? "" : model.trim();
        int separator = selected.indexOf('/');
        if (separator > 0 && separator < selected.length() - 1) {
            this.modelProvider = selected.substring(0, separator);
            this.modelId = selected.substring(separator + 1);
        } else if (!selected.isEmpty()) {
            this.modelProvider = "opencode";
            this.modelId = selected;
        } else {
            this.modelProvider = "";
            this.modelId = "";
        }
        this.http = HttpClient.newBuilder()
                .connectTimeout(this.timeout)
                .build();
    }

    public static OpenCodeTextGenerator fromConfig(AiConfig config) throws AiGenerationException {
        if (config == null || !config.isConfigured()) {
            throw new AiGenerationException(
                    "OpenCode is not configured for AI Analysis. Start OpenCode, or set ai.opencode.url "
                            + "and ai.opencode.password in config.properties.");
        }
        try {
            return new OpenCodeTextGenerator(
                    config.baseUrl(), config.password(), config.timeout(), config.model());
        } catch (IllegalArgumentException e) {
            throw new AiGenerationException(
                    "The OpenCode service URL is invalid. Check ai.opencode.url in config.properties.", e);
        }
    }

    @Override
    public String generate(String prompt) throws AiGenerationException {
        JsonObject body = new JsonObject();
        body.addProperty("prompt", prompt);
        if (!modelId.isEmpty()) {
            JsonObject modelRef = new JsonObject();
            modelRef.addProperty("providerID", modelProvider);
            modelRef.addProperty("id", modelId);
            body.add("model", modelRef);
        }

        HttpRequest request = HttpRequest.newBuilder(endpoint)
                .timeout(timeout)
                .header("Authorization", authorization)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body.toString(), StandardCharsets.UTF_8))
                .build();

        final HttpResponse<String> response;
        try {
            response = http.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new AiGenerationException(
                    "Could not reach the OpenCode service. Start OpenCode and try again.", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AiGenerationException("AI analysis was interrupted.", e);
        }

        if (response.statusCode() != 200) {
            throw new AiGenerationException(errorMessage(response.statusCode(), response.body()));
        }

        try {
            JsonObject root = JsonParser.parseString(response.body()).getAsJsonObject();
            var data = root.get("data");
            if (data == null || !data.isJsonObject()) {
                throw new AiGenerationException("The AI returned an unexpected response.");
            }
            var text = data.getAsJsonObject().get("text");
            if (text == null || !text.isJsonPrimitive() || text.getAsString().isBlank()) {
                throw new AiGenerationException("The AI returned an empty response.");
            }
            return text.getAsString();
        } catch (AiGenerationException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new AiGenerationException("The AI returned a response that could not be read.", e);
        }
    }

    /** Maps documented OpenCode HTTP errors to messages shown in the result card. */
    static String errorMessage(int status, String body) {
        JsonObject error = parseError(body);
        String tag = readString(error, "_tag");
        String detail = cleanDetail(readString(error, "message"));
        String provider = readString(error, "providerID");
        String model = readString(error, "modelID");
        String selectedModel = modelRef(provider, model);

        return switch (status) {
            case 400 -> withDetail("OpenCode rejected the AI request.", detail);
            case 401, 403 -> withDetail(
                    "OpenCode rejected the local connection. Check its service registration.", detail);
            case 404 -> switch (tag) {
                case "ModelNotFoundError" -> "OpenCode model '" + selectedModel
                        + "' was not found. Choose another model in OpenCode.";
                case "ProviderNotFoundError" -> "OpenCode provider '"
                        + (provider.isEmpty() ? "unknown" : provider)
                        + "' was not found. Connect it in OpenCode.";
                default -> "The OpenCode generation endpoint is unavailable. Update OpenCode.";
            };
            case 422 -> "OpenCode model '" + selectedModel
                    + "' does not support text generation. Choose another model.";
            case 429 -> "The AI usage limit has been reached. Try again later or change the model in OpenCode.";
            case 502 -> providerRequestMessage(readString(error, "reason"), provider);
            case 503 -> withDetail("The OpenCode service is temporarily unavailable. Try again shortly.", detail);
            default -> status >= 500
                    ? "The AI service is temporarily unavailable."
                    : "The AI request failed (HTTP " + status + ").";
        };
    }

    private static String providerRequestMessage(String reason, String provider) {
        String suffix = provider.isEmpty() ? "" : " (provider: " + provider + ")";
        return switch (reason) {
            case "rate_limit" -> "OpenCode's AI provider is out of free usage or rate-limited"
                    + suffix + ". Try again later or connect another provider in OpenCode.";
            case "authentication" -> "OpenCode's AI provider rejected its credentials"
                    + suffix + ". Reconnect the provider in OpenCode.";
            case "overloaded" -> "OpenCode's AI provider is overloaded" + suffix + ". Try again shortly.";
            case "invalid_request" -> "OpenCode rejected the generation request"
                    + suffix + ". Check the configured model.";
            case "content_filter" -> "OpenCode's AI provider blocked this content" + suffix + ".";
            default -> "OpenCode's AI provider reported an error" + suffix
                    + ". Try again or change the model in OpenCode.";
        };
    }

    private static JsonObject parseError(String body) {
        if (body == null || body.isBlank()) {
            return new JsonObject();
        }
        try {
            JsonElement parsed = JsonParser.parseString(body);
            return parsed.isJsonObject() ? parsed.getAsJsonObject() : new JsonObject();
        } catch (RuntimeException e) {
            return new JsonObject();
        }
    }

    private static String readString(JsonObject object, String name) {
        var value = object.get(name);
        if (value == null || !value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString()) {
            return "";
        }
        return value.getAsString().trim();
    }

    private static String cleanDetail(String text) {
        String detail = text.replaceAll("\\s+", " ").trim();
        if (detail.length() > MAX_ERROR_DETAIL) {
            detail = detail.substring(0, MAX_ERROR_DETAIL).trim() + "...";
        }
        return detail;
    }

    private static String withDetail(String base, String detail) {
        return detail.isEmpty() ? base : base + " " + detail;
    }

    private static String modelRef(String provider, String model) {
        if (provider.isEmpty()) {
            return model.isEmpty() ? "unknown" : model;
        }
        if (model.isEmpty()) {
            return provider;
        }
        return provider + "/" + model;
    }
}
