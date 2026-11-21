package com.threatdetector.model;

import java.util.Locale;
import java.util.Optional;

public enum ItemType {
    URL,
    MESSAGE;

    public static Optional<ItemType> fromText(String text) {
        if (text == null) {
            return Optional.empty();
        }
        return switch (text.trim().toLowerCase(Locale.ROOT)) {
            case "url" -> Optional.of(URL);
            case "message", "msg", "sms", "text" -> Optional.of(MESSAGE);
            default -> Optional.empty();
        };
    }
}
