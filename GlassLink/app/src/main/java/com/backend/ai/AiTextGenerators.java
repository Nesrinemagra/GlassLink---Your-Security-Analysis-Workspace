package com.backend.ai;

import java.util.ArrayList;
import java.util.List;

                                                                             
public final class AiTextGenerators {

    private AiTextGenerators() {
    }

       
                                                             
                                                                    
                                                                              
                                                                             
       
    public static AiTextGenerator create(AiConfig config) throws AiGenerationException {
        if (config == null) {
            throw new AiGenerationException("AI configuration is missing. Check config.properties.");
        }

        return switch (config.provider()) {
            case "opencode" -> OpenCodeTextGenerator.fromConfig(config);
            case "openai-compatible" -> OpenAiCompatibleTextGenerator.fromConfig(config);
            default -> createAuto(config);
        };
    }

    private static AiTextGenerator createAuto(AiConfig config) throws AiGenerationException {
        List<AiTextGenerator> candidates = new ArrayList<>(2);
        if (config.isOpenCodeConfigured()) {
            candidates.add(OpenCodeTextGenerator.fromConfig(config));
        }
        if (config.isOpenAiCompatibleConfigured()) {
            candidates.add(OpenAiCompatibleTextGenerator.fromConfig(config));
        }

        if (candidates.isEmpty()) {
            throw new AiGenerationException(
                    "No AI provider is configured. Start OpenCode or set ai.openai.api.key in config.properties.");
        }

        return prompt -> {
            AiGenerationException last = null;
            for (AiTextGenerator candidate : candidates) {
                try {
                    return candidate.generate(prompt);
                } catch (AiGenerationException e) {
                    last = e;
                }
            }
            throw new AiGenerationException("All configured AI providers failed. " + last.getMessage());
        };
    }
}
