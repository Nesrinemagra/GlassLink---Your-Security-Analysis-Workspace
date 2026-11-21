package com.threatdetector.service;

import com.threatdetector.model.ItemType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CsvParserTest {

    @TempDir
    Path dir;

    private final CsvReader parser = new CsvReader();

    private Path write(String content) throws IOException {
        Path file = dir.resolve("batch.csv");
        Files.writeString(file, content, StandardCharsets.UTF_8);
        return file;
    }

    @Test
    void validRowsAreKeptAndBrokenRowsReportedWithLineNumbers() throws Exception {
        Path file = write("""
                type,content
                url,https://example.com
                message,"Hello, click http://x.com now"
                email,unknown type
                url,
                message,"never closed
                url,https://a.com,extra
                """);

        CsvResult result = parser.result(file);

        assertEquals(2, result.items().size());
        assertEquals(ItemType.URL, result.items().get(0).type());
        assertEquals("Hello, click http://x.com now", result.items().get(1).content());

        assertEquals(4, result.errors().size());
        assertEquals(List.of(4, 5, 6, 7),
                result.errors().stream().map(CsvRowError::lineNumber).toList());
        assertTrue(result.errors().get(0).reason().contains("Unknown type"));
        assertTrue(result.errors().get(1).reason().contains("Empty content"));
        assertTrue(result.errors().get(2).reason().contains("Unclosed quote"));
        assertTrue(result.errors().get(3).reason().contains("Expected 2 columns"));
    }

    @Test
    void headerIsOptional() throws Exception {
        CsvResult result = parser.result(write("url,https://example.com\n"));
        assertEquals(1, result.items().size());
    }

    @Test
    void blankLinesAreIgnored() throws Exception {
        CsvResult result = parser.result(write("type,content\n\nurl,https://a.com\n\n"));
        assertEquals(1, result.items().size());
        assertTrue(result.errors().isEmpty());
    }

    @Test
    void itemsGetUniqueIds() throws Exception {
        CsvResult result = parser.result(write("url,https://a.com\nurl,https://b.com\n"));
        assertTrue(result.items().get(0).id() != result.items().get(1).id());
    }

    @Test
    void missingFileThrowsClearException() {
        CsvReadException e = assertThrows(CsvReadException.class,
                () -> parser.result(dir.resolve("does-not-exist.csv")));
        assertTrue(e.getMessage().contains("File not found"));
    }

    @Test
    void emptyFileThrows() throws Exception {
        Path file = write("   \n\n");
        assertThrows(CsvReadException.class, () -> parser.result(file));
    }

    @Test
    void quotesInsideQuotedFieldAreUnescaped() {
        assertEquals(List.of("message", "He said \"hi\", ok"),
                CsvReader.splitLine("message,\"He said \"\"hi\"\", ok\""));
        assertNull(CsvReader.splitLine("message,\"open"));
    }
}
