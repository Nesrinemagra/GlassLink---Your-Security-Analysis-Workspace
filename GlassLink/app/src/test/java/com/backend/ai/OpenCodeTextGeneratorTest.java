package com.backend.ai;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

class OpenCodeTextGeneratorTest {

    private HttpServer server;
    private String baseUrl;
    private volatile JsonObject lastRequest;
    private volatile String responseBody;
    private final AtomicInteger status = new AtomicInteger(200);

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext(OpenCodeTextGenerator.ENDPOINT, this::handle);
        server.start();
        baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
        status.set(200);
        responseBody = null;
        lastRequest = null;
    }

    @AfterEach
    void stopServer() {
        if (server != null) {
            server.stop(0);
        }
    }

    private void handle(HttpExchange exchange) throws IOException {
        String expected = "Basic " + Base64.getEncoder().encodeToString(
                "opencode:test-service-password".getBytes(StandardCharsets.UTF_8));
        assertEquals(expected, exchange.getRequestHeaders().getFirst("Authorization"));
        assertEquals("POST", exchange.getRequestMethod());

        String requestBody = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        JsonObject json = JsonParser.parseString(requestBody).getAsJsonObject();
        assertTrue(json.get("prompt").getAsString().contains("test prompt"));
        lastRequest = json;

        String body = responseBody != null
                ? responseBody
                : (status.get() == 200
                        ? "{\"data\":{\"text\":\"AI result\"}}"
                        : "{\"_tag\":\"UnauthorizedError\"}");
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status.get(), bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    @Test
    void sendsPromptToOpenCodeAndReadsText() throws Exception {
        OpenCodeTextGenerator generator =
                new OpenCodeTextGenerator(baseUrl, "test-service-password", Duration.ofSeconds(10));

        assertEquals("AI result", generator.generate("test prompt"));
        assertEquals("test prompt", lastRequest.get("prompt").getAsString());
        assertFalse(lastRequest.has("model"));
    }

    @Test
    void sendsConfiguredModelAsOpenCodeModelReference() throws Exception {
        OpenCodeTextGenerator generator = new OpenCodeTextGenerator(
                baseUrl, "test-service-password", Duration.ofSeconds(10), "opencode/big-pickle");

        generator.generate("test prompt");

        assertEquals("opencode", lastRequest.getAsJsonObject("model").get("providerID").getAsString());
        assertEquals("big-pickle", lastRequest.getAsJsonObject("model").get("id").getAsString());
    }

    @Test
    void mapsUsageLimitToFriendlyMessage() {
        status.set(429);
        OpenCodeTextGenerator generator =
                new OpenCodeTextGenerator(baseUrl, "test-service-password", Duration.ofSeconds(10));

        AiGenerationException thrown = assertThrows(AiGenerationException.class,
                () -> generator.generate("test prompt"));

        assertTrue(thrown.getMessage().contains("usage limit"));
    }

    @Test
    void mapsRateLimitedProviderToFriendlyMessage() {
        status.set(502);
        responseBody = """
                {"_tag":"ProviderRequestError","providerID":"opencode","reason":"rate_limit",
                 "message":"Free usage limit reached."}
                """;
        OpenCodeTextGenerator generator =
                new OpenCodeTextGenerator(baseUrl, "test-service-password", Duration.ofSeconds(10));

        AiGenerationException thrown = assertThrows(AiGenerationException.class,
                () -> generator.generate("test prompt"));

        assertTrue(thrown.getMessage().contains("free usage"));
        assertTrue(thrown.getMessage().contains("opencode"));
    }

    @Test
    void mapsMissingModelToFriendlyMessage() {
        status.set(404);
        responseBody = """
                {"_tag":"ModelNotFoundError","providerID":"opencode","modelID":"missing-model",
                 "message":"Model not found"}
                """;
        OpenCodeTextGenerator generator =
                new OpenCodeTextGenerator(baseUrl, "test-service-password", Duration.ofSeconds(10));

        AiGenerationException thrown = assertThrows(AiGenerationException.class,
                () -> generator.generate("test prompt"));

        assertTrue(thrown.getMessage().contains("opencode/missing-model"));
        assertTrue(thrown.getMessage().contains("not found"));
    }

    @Test
    void mapsAuthenticationErrorToFriendlyMessage() {
        status.set(401);
        responseBody = """
                {"_tag":"UnauthorizedError","message":"Authentication required"}
                """;
        OpenCodeTextGenerator generator =
                new OpenCodeTextGenerator(baseUrl, "test-service-password", Duration.ofSeconds(10));

        AiGenerationException thrown = assertThrows(AiGenerationException.class,
                () -> generator.generate("test prompt"));

        assertTrue(thrown.getMessage().contains("local connection"));
        assertTrue(thrown.getMessage().contains("Authentication required"));
    }

    @Test
    void reportsConnectionFailure() {
        OpenCodeTextGenerator generator =
                new OpenCodeTextGenerator("http://127.0.0.1:1", "test-service-password", Duration.ofSeconds(2));

        AiGenerationException thrown = assertThrows(AiGenerationException.class,
                () -> generator.generate("test prompt"));

        assertTrue(thrown.getMessage().contains("Could not reach the OpenCode service"));
    }

    @Test
    void rejectsMissingConfiguration() {
        AiGenerationException thrown = assertThrows(AiGenerationException.class,
                () -> OpenCodeTextGenerator.fromConfig(new AiConfig("", "", Duration.ofSeconds(10))));

        assertTrue(thrown.getMessage().contains("OpenCode is not configured"));
        assertTrue(thrown.getMessage().contains("ai.opencode.url"));
    }

    @Test
    void rejectsInvalidServiceUrl() {
        AiConfig config = new AiConfig("http://[bad", "service-password", Duration.ofSeconds(10));

        AiGenerationException thrown = assertThrows(AiGenerationException.class,
                () -> OpenCodeTextGenerator.fromConfig(config));

        assertTrue(thrown.getMessage().contains("URL is invalid"));
    }
}
