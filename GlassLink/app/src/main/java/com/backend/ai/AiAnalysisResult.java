package com.backend.ai;

import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Result produced by the AI analyzer.
 *
 * This is deliberately a separate model from the RuleAnalyzer / VirusTotal
 * {@code Result}: AI output is never merged into the existing detection results.
 */
public record AiAnalysisResult(
        String type,
        String status,
        String risk,
        List<String> insights,
        long durationMs) {

    public static final Set<String> ALLOWED_STATUSES = Set.of(
            "Safe", "Danger", "Suspect", "Low Risk", "Not Verified", "Error");

    public static final Set<String> ALLOWED_RISKS = Set.of("LOW", "MEDIUM", "HIGH", "UNKNOWN");

    public AiAnalysisResult {
        type = type == null || type.isBlank() ? "Unknown" : type.trim();
        status = status == null || status.isBlank() ? "Not Verified" : status.trim();
        risk = risk == null || risk.isBlank() ? "UNKNOWN" : risk.trim().toUpperCase();
        insights = insights == null ? List.of() : List.copyOf(insights.stream()
                .filter(Objects::nonNull)
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .toList());
        durationMs = Math.max(0, durationMs);
    }

    public String durationText() {
        return durationMs + " ms";
    }
}
