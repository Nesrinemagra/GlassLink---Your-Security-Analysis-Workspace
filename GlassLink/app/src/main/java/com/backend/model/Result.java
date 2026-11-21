package com.backend.model;

import java.util.List;
import java.util.Objects;

public record Result(Item item,
        Status status,
        RiskLevel riskLevel,
        int ruleScore,
        List<String> reasons,
        List<String> threatTypes,
        long durationMs
) {

    public static final int NO_RULE_SCORE = -1;

    public Result {
        Objects.requireNonNull(item, "item");
        Objects.requireNonNull(status, "status");
        riskLevel = riskLevel == null ? RiskLevel.UNKNOWN : riskLevel;
        reasons = reasons == null ? List.of() : List.copyOf(reasons);
        threatTypes = threatTypes == null ? List.of() : List.copyOf(threatTypes);
    }

    public String reasonText() {
        return String.join("; ", reasons);
    }
}
