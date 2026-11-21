package com.backend.service;

import com.backend.model.Item;

import java.nio.file.Path;
import java.util.List;

public record CsvResult(Path file, List<Item> items, List<CsvRowError> errors) {

    public CsvResult {
        items = List.copyOf(items);
        errors = List.copyOf(errors);
    }

    public boolean hasErrors() {
        return !errors.isEmpty();
    }
}
