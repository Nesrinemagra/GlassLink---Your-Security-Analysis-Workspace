package com.threatdetector.service;

import java.util.List;

import com.threatdetector.model.RiskLevel;

public record RuleScore(int score, RiskLevel level, List<String> reasons) {

    public RuleScore {
        reasons = List.copyOf(reasons);
    }
}
