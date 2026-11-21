package com.threatdetector.service;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class LinkFinder {

    private static final Pattern URL_PATTERN =
            Pattern.compile("https?://[^\\s<>\"']+", Pattern.CASE_INSENSITIVE);

    private static final String TRAILING_PUNCTUATION = ".,;:!?)]}";

    public List<String> findLinks(String text) {
        if (text == null || text.isBlank()) {
            return List.of();
        }
        Set<String> found = new LinkedHashSet<>();
        Matcher matcher = URL_PATTERN.matcher(text);
        while (matcher.find()) {
            String url = stripTrailingPunctuation(matcher.group());
            if (!url.isEmpty()) {
                found.add(url);
            }
        }
        return new ArrayList<>(found);
    }

    private static String stripTrailingPunctuation(String url) {
        int end = url.length();
        while (end > 0 && TRAILING_PUNCTUATION.indexOf(url.charAt(end - 1)) >= 0) {
            end--;
        }
        return url.substring(0, end);
    }
}
