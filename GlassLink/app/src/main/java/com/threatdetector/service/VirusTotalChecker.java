package com.threatdetector.service;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.threatdetector.config.AppConfig;
import com.threatdetector.model.ApiResponse;

public final class VirusTotalChecker implements ApiChecker {

    static final String WAIT_TIME = "https://www.virustotal.com/api/v3/urls/";

    /** How long to wait before retrying after HTTP 429 (free keys: 4 requests/minute). */
    private static final long RETRY_WAIT_MS = 15_000;
    /** A new URL is analysed by VirusTotal: poll the analysis a few times. */
    private static final int POLL_ATTEMPTS = 5;
    private static final long POLL_WAIT_MS = 3_000;

    private final HttpClient http;
    private final String urlsEndpoint;      // .../urls
    private final String analysesEndpoint;  // .../analyses
    private final String apiKey;
    private final Duration waitTimeMs;
    private final int maxRetries;

    public VirusTotalChecker(AppConfig config) {
        this(config, WAIT_TIME);
    }

    VirusTotalChecker(AppConfig config, String apiUrl) {
        this.apiKey = config.apiKey();
        this.waitTimeMs = config.timeout();
        this.maxRetries = config.maxRetries();
        String base = apiUrl.endsWith("/") ? apiUrl.substring(0, apiUrl.length() - 1) : apiUrl;
        this.urlsEndpoint = base;
        this.analysesEndpoint = base.replaceFirst("/urls$", "/analyses");
        this.http = HttpClient.newBuilder()
                .connectTimeout(waitTimeMs)
                .build();
    }

    @Override
    public ApiResponse checkUrl(String url) {
        if (apiKey.isEmpty()) {
            return ApiResponse.unavailable("VirusTotal API key not configured");
        }
        try {
            // 1. Is there already a report for this URL?
            HttpResponse<String> report = send(request(urlsEndpoint + "/" + urlId(url)).GET());
            int code = report.statusCode();
            if (code == 200) {
                return parseResponse(report.body());
            }
            if (code == 404) {
                // 2. Never analysed before: ask VirusTotal to analyse it, then read the result.
                return submitAndWait(url);
            }
            return failure(code);
        } catch (HttpTimeoutException e) {
            return ApiResponse.unavailable("API did not answer within " + waitTimeMs.toSeconds() + "s (timeout)");
        } catch (IOException e) {
            return ApiResponse.unavailable("Network error: " + describe(e));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return ApiResponse.unavailable("Check cancelled");
        }
    }

    private ApiResponse submitAndWait(String url) throws IOException, InterruptedException {
        HttpResponse<String> submit = send(request(urlsEndpoint)
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(
                        "url=" + URLEncoder.encode(url, StandardCharsets.UTF_8))));
        if (submit.statusCode() != 200) {
            return failure(submit.statusCode());
        }
        String analysisId = readAnalysisId(submit.body());
        if (analysisId == null) {
            return ApiResponse.unavailable("Invalid API response (no analysis id)");
        }

        for (int i = 0; i < POLL_ATTEMPTS; i++) {
            Thread.sleep(POLL_WAIT_MS);
            HttpResponse<String> poll = send(request(analysesEndpoint + "/" + analysisId).GET());
            if (poll.statusCode() != 200) {
                return failure(poll.statusCode());
            }
            ApiResponse parsed = parseAnalysis(poll.body());
            if (!parsed.reason().startsWith(STILL_RUNNING)) {
                return parsed;
            }
        }
        return ApiResponse.unavailable("VirusTotal analysis is still running - try again in a moment");
    }

    private HttpRequest.Builder request(String uri) {
        return HttpRequest.newBuilder()
                .uri(URI.create(uri))
                .timeout(waitTimeMs)
                .header("x-apikey", apiKey)
                .header("Accept", "application/json");
    }

    /** Sends the request; waits and retries when VirusTotal answers 429 (rate limit). */
    private HttpResponse<String> send(HttpRequest.Builder builder) throws IOException, InterruptedException {
        HttpResponse<String> response = http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        for (int attempt = 1; response.statusCode() == 429 && attempt <= maxRetries; attempt++) {
            Thread.sleep(RETRY_WAIT_MS);
            response = http.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        }
        return response;
    }

    private static ApiResponse failure(int code) {
        if (code == 401 || code == 403) {
            return ApiResponse.unavailable("Invalid VirusTotal API key (HTTP " + code + ")");
        }
        if (code == 429) {
            return ApiResponse.unavailable("VirusTotal rate limit reached (HTTP 429) - wait a minute and retry");
        }
        return ApiResponse.unavailable("Unexpected VirusTotal API response (HTTP " + code + ")");
    }

    static String urlId(String url) {
        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(url.getBytes(StandardCharsets.UTF_8));
    }

    private static final String STILL_RUNNING = "VirusTotal analysis not finished";

    /** Reads an existing URL report (GET /urls/{id}). */
    static ApiResponse parseResponse(String body) {
        try {
            JsonObject attributes = attributesOf(body);
            JsonElement statsElement = attributes.get("last_analysis_stats");
            if (statsElement == null || !statsElement.isJsonObject()) {
                return ApiResponse.unavailable("Invalid API response (missing last_analysis_stats)");
            }
            return verdict(statsElement.getAsJsonObject());
        } catch (IllegalArgumentException e) {
            return ApiResponse.unavailable(e.getMessage());
        } catch (RuntimeException e) {
            return ApiResponse.unavailable("Invalid API response (could not parse JSON)");
        }
    }

    /** Reads a finished analysis (GET /analyses/{id}). */
    static ApiResponse parseAnalysis(String body) {
        try {
            JsonObject attributes = attributesOf(body);
            JsonElement status = attributes.get("status");
            if (status == null || !"completed".equals(status.getAsString())) {
                return ApiResponse.unavailable(STILL_RUNNING + " yet");
            }
            JsonElement statsElement = attributes.get("stats");
            if (statsElement == null || !statsElement.isJsonObject()) {
                return ApiResponse.unavailable("Invalid API response (missing stats)");
            }
            return verdict(statsElement.getAsJsonObject());
        } catch (IllegalArgumentException e) {
            return ApiResponse.unavailable(e.getMessage());
        } catch (RuntimeException e) {
            return ApiResponse.unavailable("Invalid API response (could not parse JSON)");
        }
    }

    private static String readAnalysisId(String body) {
        try {
            JsonObject data = JsonParser.parseString(body).getAsJsonObject().getAsJsonObject("data");
            return data.get("id").getAsString();
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static JsonObject attributesOf(String body) {
        JsonElement root = JsonParser.parseString(body == null ? "" : body);
        if (!root.isJsonObject()) {
            throw new IllegalArgumentException("Invalid API response (not a JSON object)");
        }
        JsonElement dataElement = root.getAsJsonObject().get("data");
        if (dataElement == null || !dataElement.isJsonObject()) {
            throw new IllegalArgumentException("Invalid API response (missing data)");
        }
        JsonElement attributesElement = dataElement.getAsJsonObject().get("attributes");
        if (attributesElement == null || !attributesElement.isJsonObject()) {
            throw new IllegalArgumentException("Invalid API response (missing attributes)");
        }
        return attributesElement.getAsJsonObject();
    }

    /** Turns scanner counts into a verdict. All-zero counts are NOT treated as clean. */
    private static ApiResponse verdict(JsonObject stats) {
        long malicious = readCount(stats, "malicious");
        long suspicious = readCount(stats, "suspicious");
        long harmless = readCount(stats, "harmless");
        long undetected = readCount(stats, "undetected");
        long scanners = malicious + suspicious + harmless + undetected;

        if (malicious > 0 || suspicious > 0) {
            List<String> indicators = new ArrayList<>();
            if (malicious > 0) indicators.add("malicious: " + malicious + " of " + scanners + " scanners");
            if (suspicious > 0) indicators.add("suspicious: " + suspicious + " of " + scanners + " scanners");
            return ApiResponse.listed(indicators);
        }
        if (scanners == 0) {
            return ApiResponse.unavailable("VirusTotal returned no scanner results for this URL yet");
        }
        return new ApiResponse(ApiResponse.Response.NOT_LISTED, List.of(),
                "No security scanner flagged this URL (" + scanners + " scanners checked)");
    }

    private static long readCount(JsonObject stats, String name) {
        JsonElement value = stats.get(name);
        if (value == null || !value.isJsonPrimitive() || !value.getAsJsonPrimitive().isNumber()) {
            return 0;
        }
        return value.getAsLong();
    }

    private static String describe(IOException e) {
        String message = e.getMessage();
        return (message == null || message.isBlank()) ? e.getClass().getSimpleName() : message;
    }
}
