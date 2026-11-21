package com.backend.service;

import java.util.List;

import com.backend.model.RiskLevel;

public record RuleScore(int score, RiskLevel level, List<String> reasons) {

    public RuleScore {
        reasons = List.copyOf(reasons);
    }
}
