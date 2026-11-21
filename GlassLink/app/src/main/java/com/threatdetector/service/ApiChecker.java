package com.threatdetector.service;

import com.threatdetector.model.ApiResponse;

public interface ApiChecker {

    ApiResponse checkUrl(String url);
}
