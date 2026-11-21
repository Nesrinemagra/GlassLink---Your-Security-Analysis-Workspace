package com.backend.ai;

/** A user-facing failure of the AI backend. Messages never contain credentials. */
public class AiGenerationException extends Exception {

    public AiGenerationException(String message) {
        super(message);
    }

    public AiGenerationException(String message, Throwable cause) {
        super(message, cause);
    }
}
