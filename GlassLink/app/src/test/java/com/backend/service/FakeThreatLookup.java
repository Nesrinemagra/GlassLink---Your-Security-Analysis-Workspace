package com.backend.service;

import com.backend.model.ApiResponse;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

class FakeThreatLookup implements ApiChecker {

    private final long delayMs;
    final AtomicInteger calls = new AtomicInteger();
    final Map<String, Integer> callsPerUrl = new ConcurrentHashMap<>();

    FakeThreatLookup() {
        this(0);
    }

    FakeThreatLookup(long delayMs) {
        this.delayMs = delayMs;
    }

    @Override
    public ApiResponse checkUrl(String url) {
        calls.incrementAndGet();
        callsPerUrl.merge(url, 1, Integer::sum);

        if (delayMs > 0) {
            try {
                Thread.sleep(delayMs);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return ApiResponse.unavailable("Check cancelled");
            }
        }
        if (url.contains("crash")) {
            throw new IllegalStateException("simulated bug");
        }
        if (url.contains("null")) {
            return null;
        }
        if (url.contains("down")) {
            return ApiResponse.unavailable("API did not answer within 5s (timeout)");
        }
        if (url.contains("evil")) {
            return ApiResponse.listed(List.of("SOCIAL_ENGINEERING"));
        }
        return ApiResponse.notListed();
    }
}
