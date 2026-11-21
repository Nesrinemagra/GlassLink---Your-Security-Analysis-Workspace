package com.backend.ai;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

class OpenAiCompatibleTextGeneratorTest {

    private HttpServer server;
    private String baseUrl;
    private volatile JsonObject lastRequest;
    private volatile String responseBody;
    private final AtomicInteger status = new AtomicInteger(200);

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext(OpenAiCompatibleTextGenerator.CHAT_COMPLETIONS_PATH, this::handle);
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
        assertEquals("Bearer test-api-key", exchange.getRequestHeaders().getFirst("Authorization"));
        assertEquals("POST", exchange.getRequestMethod());
        assertEquals("application/json", exchange.getRequestHeaders().getFirst("Content-Type"));
        lastRequest = JsonParser.parseString(
                new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8)).getAsJsonObject();

        String body = responseBody != null
                ? responseBody
                : (status.get() == 200 ? chatResponse("AI result") : "{\"error\":{\"message\":\"Rejected\"}}");
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status.get(), bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    private static String chatResponse(String content) {
        JsonObject message = new JsonObject();
        message.addProperty("role", "assistant");
        message.addProperty("content", content);
        JsonObject choice = new JsonObject();
        choice.add("message", message);
        JsonArray choices = new JsonArray();
        choices.add(choice);
        JsonObject root = new JsonObject();
        root.add("choices", choices);
        return root.toString();
    }

    private OpenAiCompatibleTextGenerator generator() {
        return new OpenAiCompatibleTextGenerator(baseUrl, "test-api-key", "openai/gpt-oss-20b",
                Duration.ofSeconds(10));
    }

    @Test
    void sendsBearerKeyAndReadsAssistantContent() throws Exception {
        assertEquals("AI result", generator().generate("test prompt"));

        assertEquals("openai/gpt-oss-20b", lastRequest.get("model").getAsString());
        assertEquals(0.1, lastRequest.get("temperature").getAsDouble(), 0.0001);
        assertEquals("test prompt", lastRequest.getAsJsonArray("messages").get(1).getAsJsonObject()
                .get("content").getAsString());
    }

    @Test
    void analyzesUrlThroughOpenAiCompatibleProvider() throws Exception {
        responseBody = chatResponse("""
                {"type":"URL","status":"Danger","risk":"HIGH",
                 "insights":["The domain uses a lookalike brand spelling.",
                             "The page urges immediate verification."]}
                """);

        AiAnalysisResult result = new AiAnalyzer(generator()).analyze("https://paypa1.example/verify", "Auto Detect");

        assertEquals("URL", result.type());
        assertEquals("Danger", result.status());
        assertEquals("HIGH", result.risk());
        assertEquals(2, result.insights().size());
        assertTrue(result.insights().get(0).contains("lookalike"));
    }

    @Test
    void analyzesMessageThroughOpenAiCompatibleProvider() throws Exception {
        responseBody = chatResponse("""
                {"type":"Message","status":"Suspect","risk":"MEDIUM",
                 "insights":["The message creates urgency.",
                             "It asks the recipient to reveal a password."]}
                """);

        AiAnalysisResult result = new AiAnalyzer(generator())
                .analyze("Verify your password now before your account closes.", "Auto Detect");

        assertEquals("Message", result.type());
        assertEquals("Suspect", result.status());
        assertEquals("MEDIUM", result.risk());
        assertEquals(2, result.insights().size());
    }

    @Test
    void mapsAuthenticationErrorToKeyHint() {
        status.set(401);

        AiGenerationException thrown = assertThrows(AiGenerationException.class,
                () -> generator().generate("test prompt"));

        assertTrue(thrown.getMessage().contains("ai.openai.api.key"));
        assertTrue(thrown.getMessage().contains("Rejected"));
    }

    @Test
    void mapsRateLimitToFriendlyMessage() {
        status.set(429);

        AiGenerationException thrown = assertThrows(AiGenerationException.class,
                () -> generator().generate("test prompt"));

        assertTrue(thrown.getMessage().contains("rate limit"));
    }

    @Test
    void rejectsMissingKey() {
        assertThrows(IllegalArgumentException.class,
                () -> new OpenAiCompatibleTextGenerator(baseUrl, "", "openai/gpt-oss-20b", Duration.ofSeconds(10)));
    }
}
