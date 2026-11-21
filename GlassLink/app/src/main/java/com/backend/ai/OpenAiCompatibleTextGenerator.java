package com.backend.ai;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

/**
 * OpenAI-compatible text provider used as the free Groq fallback.
 *
 * The key is supplied only from backend configuration; no UI component ever
 * sees it. Groq exposes the OpenAI chat-completions API at
 * {@code https://api.groq.com/openai/v1/chat/completions}.
 */
public final class OpenAiCompatibleTextGenerator implements AiTextGenerator {

    static final String CHAT_COMPLETIONS_PATH = "/chat/completions";
    private static final int MAX_ERROR_DETAIL = 180;

    private final URI endpoint;
    private final String authorization;
    private final String model;
    private final HttpClient http;
    private final Duration timeout;

    public OpenAiCompatibleTextGenerator(String baseUrl, String apiKey, String model, Duration timeout) {
        String base = baseUrl == null ? "" : baseUrl.trim();
        while (base.endsWith("/")) {
            base = base.substring(0, base.length() - 1);
        }
        if (base.isEmpty()) {
            throw new IllegalArgumentException("baseUrl");
        }
        String key = apiKey == null ? "" : apiKey.trim();
        if (key.isEmpty()) {
            throw new IllegalArgumentException("apiKey");
        }
        String selectedModel = model == null ? "" : model.trim();
        if (selectedModel.isEmpty()) {
            throw new IllegalArgumentException("model");
        }

        this.endpoint = URI.create(base + CHAT_COMPLETIONS_PATH);
        this.authorization = "Bearer " + key;
        this.model = selectedModel;
        this.timeout = timeout == null ? Duration.ofSeconds(60) : timeout;
        this.http = HttpClient.newBuilder()
                .connectTimeout(this.timeout)
                .build();
    }

    public static OpenAiCompatibleTextGenerator fromConfig(AiConfig config) throws AiGenerationException {
        if (config == null || !config.isOpenAiCompatibleConfigured()) {
            throw new AiGenerationException(
                    "The OpenAI-compatible AI provider is not configured. Set ai.openai.api.key "
                            + "in config.properties (or GROQ_API_KEY in the backend environment).");
        }
        try {
            return new OpenAiCompatibleTextGenerator(
                    config.providerBaseUrl(), config.providerKey(), config.providerModel(), config.timeout());
        } catch (RuntimeException e) {
            throw new AiGenerationException(
                    "The OpenAI-compatible provider URL is invalid. Check ai.openai.base.url in config.properties.", e);
        }
    }

    @Override
    public String generate(String prompt) throws AiGenerationException {
        JsonObject system = new JsonObject();
        system.addProperty("role", "system");
        system.addProperty("content", "You are a precise security analyst. Follow the user's output format exactly.");

        JsonObject user = new JsonObject();
        user.addProperty("role", "user");
        user.addProperty("content", prompt == null ? "" : prompt);

        JsonArray messages = new JsonArray();
        messages.add(system);
        messages.add(user);

        JsonObject body = new JsonObject();
        body.addProperty("model", model);
        body.add("messages", messages);
        // Groq maps 0 to 1e-8, so use a small positive value for deterministic output.
        body.addProperty("temperature", 0.1);

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
                    "Could not reach the AI provider. Check the network connection and ai.openai.base.url.", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AiGenerationException("AI analysis was interrupted.", e);
        }

        if (response.statusCode() != 200) {
            throw new AiGenerationException(errorMessage(response.statusCode(), response.body()));
        }

        try {
            JsonObject root = JsonParser.parseString(response.body()).getAsJsonObject();
            JsonArray choices = root.getAsJsonArray("choices");
            if (choices == null || choices.size() == 0) {
                throw new AiGenerationException("The AI returned no choices.");
            }
            JsonObject message = choices.get(0).getAsJsonObject().getAsJsonObject("message");
            JsonElement content = message == null ? null : message.get("content");
            if (content == null || !content.isJsonPrimitive() || content.getAsString().isBlank()) {
                throw new AiGenerationException("The AI returned an empty response.");
            }
            return content.getAsString();
        } catch (AiGenerationException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new AiGenerationException("The AI returned a response that could not be read.", e);
        }
    }

    /** Maps common OpenAI-compatible HTTP errors to messages shown in the result card. */
    static String errorMessage(int status, String body) {
        String detail = cleanDetail(readErrorDetail(body));
        String suffix = detail.isEmpty() ? "" : " " + detail;

        return switch (status) {
            case 400 -> "The AI provider rejected the request. Check ai.openai.model in config.properties." + suffix;
            case 401, 403 -> "The AI provider rejected ai.openai.api.key in config.properties." + suffix;
            case 404 -> "The AI model or base URL was not found. Check ai.openai.model and ai.openai.base.url."
                    + suffix;
            case 429 -> "The AI provider rate limit was reached. Wait a moment and try again." + suffix;
            default -> status >= 500
                    ? "The AI provider is temporarily unavailable. Try again shortly." + suffix
                    : "The AI request failed (HTTP " + status + ")." + suffix;
        };
    }

    private static String readErrorDetail(String body) {
        if (body == null || body.isBlank()) {
            return "";
        }
        try {
            JsonElement parsed = JsonParser.parseString(body);
            if (!parsed.isJsonObject()) {
                return "";
            }
            JsonObject error = parsed.getAsJsonObject().getAsJsonObject("error");
            JsonElement message = error == null ? parsed.getAsJsonObject().get("message")
                    : error.get("message");
            return message != null && message.isJsonPrimitive() ? message.getAsString() : "";
        } catch (RuntimeException e) {
            return "";
        }
    }

    private static String cleanDetail(String text) {
        String detail = text.replaceAll("\\s+", " ").trim();
        if (detail.length() > MAX_ERROR_DETAIL) {
            detail = detail.substring(0, MAX_ERROR_DETAIL).trim() + "...";
        }
        return detail;
    }
}
