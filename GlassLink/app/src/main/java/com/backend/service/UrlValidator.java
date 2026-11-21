package com.backend.service;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;
import java.util.Optional;

public final class UrlValidator {

    public Optional<String> isTextValid(String content) {
        if (content == null || content.isBlank()) {
            return Optional.of("Input is empty");
        }
        return Optional.empty();
    }

    public Optional<String> isUrlValid(String url) {
        Optional<String> empty = isTextValid(url);
        if (empty.isPresent()) {
            return empty;
        }

        URI uri;
        try {
            uri = new URI(url.trim());
        } catch (URISyntaxException e) {
            return Optional.of("Malformed URL: " + e.getReason());
        }

        String scheme = uri.getScheme();
        if (scheme == null) {
            return Optional.of("URL must start with http:// or https://");
        }
        scheme = scheme.toLowerCase(Locale.ROOT);
        if (!scheme.equals("http") && !scheme.equals("https")) {
            return Optional.of("Unsupported URL scheme '" + scheme + "' (only http and https)");
        }
        if (uri.getHost() == null || uri.getHost().isBlank()) {
            return Optional.of("URL has no valid host");
        }
        return Optional.empty();
    }
}
