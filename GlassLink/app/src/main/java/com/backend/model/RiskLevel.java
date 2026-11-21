package com.backend.model;

public enum RiskLevel {
    LOW("Low"),
    MEDIUM("Medium"),
    HIGH("High"),
    UNKNOWN("Not Verified");

    private final String label;

    RiskLevel(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }

}
