package com.backend.ai;

                                                                                    
@FunctionalInterface
public interface AiTextGenerator {
    String generate(String prompt) throws AiGenerationException;
}
