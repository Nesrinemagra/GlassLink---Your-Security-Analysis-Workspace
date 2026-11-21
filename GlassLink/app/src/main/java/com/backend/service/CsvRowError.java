package com.backend.service;

public record CsvRowError(int lineNumber, String line, String reason) {

    @Override
    public String toString() {
        return "Line " + lineNumber + ": " + reason + "  ->  " + line;
    }
}
