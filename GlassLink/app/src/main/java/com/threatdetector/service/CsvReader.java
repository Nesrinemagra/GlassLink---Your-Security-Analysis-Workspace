 package com.threatdetector.service;

import java.io.IOException;
import java.nio.charset.MalformedInputException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import com.threatdetector.model.Item;
import com.threatdetector.model.ItemType;

public final class CsvReader {

    private static final String HEADER = "type,content";

    public CsvResult result(Path file) throws CsvReadException {
        if (file == null) {
            throw new CsvReadException("No file selected");
        }
        if (!Files.exists(file)) {
            throw new CsvReadException("File not found: " + file);
        }
        if (!Files.isRegularFile(file)) {
            throw new CsvReadException("Not a file: " + file);
        }

        List<String> lines;
        try {
            lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        } catch (MalformedInputException e) {
            throw new CsvReadException("File is not valid UTF-8 text: " + file, e);
        } catch (IOException e) {
            throw new CsvReadException("Cannot read file " + file + ": " + e.getMessage(), e);
        }

        if (lines.stream().allMatch(String::isBlank)) {
            throw new CsvReadException("CSV file is empty: " + file);
        }

        List<Item> items = new ArrayList<>();
        List<CsvRowError> errors = new ArrayList<>();
        boolean firstContentLine = true;

        for (int i = 0; i < lines.size(); i++) {
            int lineNumber = i + 1;
            String line = lines.get(i);
            if (i == 0) {
                line = stripBom(line);
            }
            if (line.isBlank()) {
                continue;
            }

            if (firstContentLine) {
                firstContentLine = false;
                if (line.trim().replace(" ", "").equalsIgnoreCase(HEADER)) {
                    continue;
                }
            }

            parseRow(line, lineNumber, items, errors);
        }
        return new CsvResult(file, items, errors);
    }

    private void parseRow(String line, int lineNumber, List<Item> items, List<CsvRowError> errors) {
        List<String> fields = splitLine(line);
        if (fields == null) {
            errors.add(new CsvRowError(lineNumber, line, "Unclosed quote"));
            return;
        }
        if (fields.size() != 2) {
            errors.add(new CsvRowError(lineNumber, line,
                    "Expected 2 columns (type,content) but found " + fields.size()));
            return;
        }

        Optional<ItemType> type = ItemType.fromText(fields.get(0));
        if (type.isEmpty()) {
            errors.add(new CsvRowError(lineNumber, line,
                    "Unknown type '" + fields.get(0).trim() + "' (expected url or message)"));
            return;
        }

        String content = fields.get(1).trim();
        if (content.isEmpty()) {
            errors.add(new CsvRowError(lineNumber, line, "Empty content"));
            return;
        }

        items.add(Item.create(type.get(), content));
    }

    static List<String> splitLine(String line) {
        List<String> fields = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean inQuotes = false;

        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (inQuotes) {
                if (c == '"') {
                    boolean escapedQuote = i + 1 < line.length() && line.charAt(i + 1) == '"';
                    if (escapedQuote) {
                        current.append('"');
                        i++;
                    } else {
                        inQuotes = false;
                    }
                } else {
                    current.append(c);
                }
            } else if (c == '"') {
                inQuotes = true;
            } else if (c == ',') {
                fields.add(current.toString());
                current.setLength(0);
            } else {
                current.append(c);
            }
        }

        if (inQuotes) {
            return null;
        }
        fields.add(current.toString());
        return fields;
    }

    private static String stripBom(String line) {
        return line.startsWith("﻿") ? line.substring(1) : line;
    }
}
