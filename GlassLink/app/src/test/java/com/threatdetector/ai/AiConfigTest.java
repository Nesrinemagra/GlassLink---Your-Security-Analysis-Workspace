package com.threatdetector.ai;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AiConfigTest {

    @TempDir
    Path temp;

    @Test
    void readsOpenCodeServiceRegistration() throws Exception {
        Path service = temp.resolve("service.json");
        Files.writeString(service, """
                {"url":"http://127.0.0.1:12345","password":"local-service-password","pid":42}
                """);
        Path config = temp.resolve("config.properties");
        Files.writeString(config, "ai.opencode.service-file=" + service.toString().replace('\\', '/') + "\n"
                + "ai.opencode.model=opencode/big-pickle\n"
                + "ai.timeout.seconds=12\n");

        AiConfig loaded = AiConfig.load(config);

        assertEquals("http://127.0.0.1:12345", loaded.baseUrl());
        assertEquals("local-service-password", loaded.password());
        assertEquals(12, loaded.timeout().toSeconds());
        assertEquals("opencode/big-pickle", loaded.model());
        assertEquals("auto", loaded.provider());
        assertTrue(loaded.isConfigured());
    }

    @Test
    void readsOpenAiCompatibleFallbackSettings() throws Exception {
        Path service = temp.resolve("service.json");
        Files.writeString(service, """
                {"url":"http://127.0.0.1:12345","password":"local-service-password"}
                """);
        Path config = temp.resolve("config.properties");
        Files.writeString(config, "ai.opencode.service-file=" + service.toString().replace('\\', '/') + "\n"
                + "ai.provider=openai-compatible\n"
                + "ai.openai.base.url=https://api.groq.com/openai/v1\n"
                + "ai.openai.api.key=unit-test-key\n"
                + "ai.openai.model=openai/gpt-oss-20b\n");

        AiConfig loaded = AiConfig.load(config);

        assertEquals("openai-compatible", loaded.provider());
        assertEquals("https://api.groq.com/openai/v1", loaded.providerBaseUrl());
        assertEquals("unit-test-key", loaded.providerKey());
        assertEquals("openai/gpt-oss-20b", loaded.providerModel());
        assertTrue(loaded.isOpenAiCompatibleConfigured());
    }

    @Test
    void placeholderKeyIsTreatedAsMissing() {
        AiConfig loaded = new AiConfig("http://127.0.0.1:12345", "service-password",
                Duration.ofSeconds(10), "opencode/big-pickle", "openai-compatible",
                "https://api.groq.com/openai/v1", "PASTE_GROQ_API_KEY_HERE", "openai/gpt-oss-20b");

        assertFalse(loaded.isOpenAiCompatibleConfigured());
        assertEquals("", loaded.providerKey());
    }

    @Test
    void missingRegistrationLeavesAiUnconfigured() throws Exception {
        Path config = temp.resolve("config.properties");
        Files.writeString(config, "ai.opencode.service-file="
                + temp.resolve("missing.json").toString().replace('\\', '/') + "\n");

        AiConfig loaded = AiConfig.load(config);

        assertFalse(loaded.isConfigured());
    }
}
