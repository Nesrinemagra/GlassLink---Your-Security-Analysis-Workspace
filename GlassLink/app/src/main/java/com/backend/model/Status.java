package com.backend.model;

public enum Status {
    SAFE("Safe"),
    DANGER("Danger"),
    SUSPECT("Suspect"),
    LOW_RISK("Low Risk"),
    NOT_VERIFIED("Not Verified"),
    ERROR("Error");

    private final String label;

    Status(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }

}
