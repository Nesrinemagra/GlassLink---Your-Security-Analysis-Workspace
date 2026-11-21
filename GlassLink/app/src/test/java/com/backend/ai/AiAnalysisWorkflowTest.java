package com.backend.ai;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

/** End-to-end workflows through AiAnalyzer and the real OpenCode HTTP client. */
class AiAnalysisWorkflowTest {

    private HttpServer server;
    private String baseUrl;
    private volatile JsonObject lastRequest;
    private volatile String responseBody;
    private volatile int responseStatus;

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext(OpenCodeTextGenerator.ENDPOINT, this::handle);
        server.start();
        baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
        responseStatus = 200;
        responseBody = "";
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
                "opencode:workflow-password".getBytes(StandardCharsets.UTF_8));
        assertEquals(expected, exchange.getRequestHeaders().getFirst("Authorization"));
        assertEquals("POST", exchange.getRequestMethod());
        assertEquals("application/json", exchange.getRequestHeaders().getFirst("Content-Type"));
        lastRequest = JsonParser.parseString(
                new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8)).getAsJsonObject();

        byte[] bytes = responseBody.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(responseStatus, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    private static String openCodeResponse(String assistantText) {
        JsonObject data = new JsonObject();
        data.addProperty("text", assistantText);
        JsonObject root = new JsonObject();
        root.add("data", data);
        return root.toString();
    }

    private AiAnalyzer analyzer() {
        return new AiAnalyzer(new OpenCodeTextGenerator(
                baseUrl, "workflow-password", Duration.ofSeconds(10), "opencode/big-pickle"));
    }

    @Test
    void analyzesUrlThroughOpenCode() throws Exception {
        responseBody = openCodeResponse("""
                {"type":"URL","status":"Danger","risk":"HIGH",
                 "insights":["The domain uses a lookalike brand spelling.",
                             "The page urges immediate verification.",
                             "It asks for account credentials."]}
                """);

        AiAnalysisResult result = analyzer().analyze("https://paypa1.example/verify", "Auto Detect");

        assertEquals("URL", result.type());
        assertEquals("Danger", result.status());
        assertEquals("HIGH", result.risk());
        assertEquals(3, result.insights().size());
        assertTrue(result.insights().get(0).contains("lookalike"));
        assertTrue(result.durationText().endsWith(" ms"));

        String prompt = lastRequest.get("prompt").getAsString();
        assertTrue(prompt.contains("Input type: URL"));
        assertTrue(prompt.contains("https://paypa1.example/verify"));
        assertEquals("opencode", lastRequest.getAsJsonObject("model").get("providerID").getAsString());
        assertEquals("big-pickle", lastRequest.getAsJsonObject("model").get("id").getAsString());
    }

    @Test
    void analyzesMessageThroughOpenCode() throws Exception {
        responseBody = openCodeResponse("""
                {"type":"Message","status":"Suspect","risk":"MEDIUM",
                 "insights":["The message creates urgency.",
                             "It asks the recipient to reveal a password."]}
                """);

        AiAnalysisResult result = analyzer().analyze("Verify your password now before your account closes.", "Auto Detect");

        assertEquals("Message", result.type());
        assertEquals("Suspect", result.status());
        assertEquals("MEDIUM", result.risk());
        assertEquals(2, result.insights().size());
        assertTrue(result.insights().get(1).contains("password"));

        String prompt = lastRequest.get("prompt").getAsString();
        assertTrue(prompt.contains("Input type: Message"));
        assertTrue(prompt.contains("Verify your password now"));
    }

    @Test
    void providerQuotaErrorIsShownThroughAnalyzer() {
        responseStatus = 502;
        responseBody = """
                {"_tag":"ProviderRequestError","providerID":"opencode","reason":"rate_limit",
                 "message":"Free usage limit reached."}
                """;

        AiGenerationException thrown = assertThrows(AiGenerationException.class,
                () -> analyzer().analyze("https://example.com", "URL"));

        assertTrue(thrown.getMessage().contains("free usage"));
        assertTrue(thrown.getMessage().contains("opencode"));
    }
}
