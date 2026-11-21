package com.backend.model;

import java.util.List;
import java.util.Objects;

public record ApiResponse(Response response , List<String> threatTypes, String reason) {

    public enum Response {
        LISTED, NOT_LISTED, UNAVAILABLE
    }

    public ApiResponse {
        Objects.requireNonNull(response, "response");
        threatTypes = threatTypes == null ? List.of() : List.copyOf(threatTypes);
        reason = reason == null ? "" : reason;
    }

    public static ApiResponse listed(List<String> threatTypes) {
        return new ApiResponse(Response.LISTED, threatTypes,
                "Listed by VirusTotal: " + String.join(", ", threatTypes));
    }

    public static ApiResponse notListed() {
        return new ApiResponse(Response.NOT_LISTED, List.of(),
                "Not found in VirusTotal threat lists");
    }

    public static ApiResponse unavailable(String reason) {
        return new ApiResponse(Response.UNAVAILABLE, List.of(), reason);
    }
}
