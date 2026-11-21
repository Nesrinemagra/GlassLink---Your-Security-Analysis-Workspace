package com.threatdetector.ai;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

class AiTextGeneratorsTest {

    private HttpServer server;
    private String baseUrl;

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext(OpenAiCompatibleTextGenerator.CHAT_COMPLETIONS_PATH, this::handle);
        server.start();
        baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @AfterEach
    void stopServer() {
        if (server != null) {
            server.stop(0);
        }
    }

    private void handle(HttpExchange exchange) throws IOException {
        String body = """
                {"choices":[{"message":{"role":"assistant","content":"fallback result"}}]}
                """;
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    private AiConfig fallbackConfig(String provider) {
        return new AiConfig("http://127.0.0.1:1", "service-password", Duration.ofSeconds(2),
                "opencode/big-pickle", provider, baseUrl, "test-api-key", "openai/gpt-oss-20b");
    }

    @Test
    void forcesOpenAiCompatibleProvider() throws Exception {
        AiTextGenerator generator = AiTextGenerators.create(fallbackConfig("openai-compatible"));

        assertEquals("fallback result", generator.generate("test prompt"));
    }

    @Test
    void autoFallsBackWhenOpenCodeIsUnavailable() throws Exception {
        AiTextGenerator generator = AiTextGenerators.create(fallbackConfig("auto"));

        assertEquals("fallback result", generator.generate("test prompt"));
    }

    @Test
    void autoReportsWhenNoProviderIsConfigured() {
        AiConfig config = new AiConfig("", "", Duration.ofSeconds(2), "", "auto",
                baseUrl, "PASTE_GROQ_API_KEY_HERE", "openai/gpt-oss-20b");

        AiGenerationException thrown = assertThrows(AiGenerationException.class,
                () -> AiTextGenerators.create(config));

        assertTrue(thrown.getMessage().contains("No AI provider is configured"));
    }

    @Test
    void forcesOpenCodeProvider() {
        AiConfig config = new AiConfig("", "", Duration.ofSeconds(2), "", "opencode",
                baseUrl, "test-api-key", "openai/gpt-oss-20b");

        AiGenerationException thrown = assertThrows(AiGenerationException.class,
                () -> AiTextGenerators.create(config));

        assertTrue(thrown.getMessage().contains("OpenCode is not configured"));
    }
}
