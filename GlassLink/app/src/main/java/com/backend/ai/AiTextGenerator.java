package com.backend.ai;

/** Minimal seam between the analyzer and the text provider (also used by tests). */
@FunctionalInterface
public interface AiTextGenerator {
    String generate(String prompt) throws AiGenerationException;
}
