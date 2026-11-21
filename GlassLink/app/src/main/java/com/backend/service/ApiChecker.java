package com.backend.service;

import com.backend.model.ApiResponse;

public interface ApiChecker {

    ApiResponse checkUrl(String url);
}
