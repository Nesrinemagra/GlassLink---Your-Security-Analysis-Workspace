package com.backend.service;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import com.backend.model.ApiResponse;
import com.backend.model.Item;
import com.backend.model.ItemType;
import com.backend.model.Result;
import com.backend.model.RiskLevel;
import com.backend.model.Status;

public final class Orchestrator {

    private final ApiChecker lookup;
    private final UrlValidator validator;
    private final LinkFinder linkFinder;
    private final RuleAnalyzer rules;

    public Orchestrator(ApiChecker lookup) {
        this(lookup, new UrlValidator(), new LinkFinder(), new RuleAnalyzer());
    }

    public Orchestrator(ApiChecker lookup, UrlValidator validator,
                        LinkFinder linkFinder, RuleAnalyzer rules) {
        this.lookup = Objects.requireNonNull(lookup, "lookup");
        this.validator = Objects.requireNonNull(validator, "validator");
        this.linkFinder = Objects.requireNonNull(linkFinder, "linkFinder");
        this.rules = Objects.requireNonNull(rules, "rules");

    }

    public Result evaluate(Item item) {
        Objects.requireNonNull(item, "item");
        long startTime = System.nanoTime();
        try {
            Optional<String> emptyError = validator.isTextValid(item.content());
            if (emptyError.isPresent()) {
                return result(item, Status.ERROR, RiskLevel.UNKNOWN, Result.NO_RULE_SCORE,
                        List.of(emptyError.get()), List.of(), startTime);
            }
            return item.type() == ItemType.URL
                    ? evaluateUrl(item, startTime)
                    : evaluateMessage(item, startTime);
        } catch (RuntimeException e) {

            return result(item, Status.NOT_VERIFIED, RiskLevel.UNKNOWN, Result.NO_RULE_SCORE,
                    List.of("Unexpected error: " + e.getClass().getSimpleName()
                            + (e.getMessage() == null ? "" : " - " + e.getMessage())),
                    List.of(), startTime);
        }
    }

    private Result evaluateUrl(Item item, long startTime) {
        String url = item.content().trim();
        Optional<String> urlError = validator.isUrlValid(url);
        if (urlError.isPresent()) {
            // A URL that cannot be parsed cannot be checked: Not Verified, never Safe.
            return result(item, Status.NOT_VERIFIED, RiskLevel.UNKNOWN, Result.NO_RULE_SCORE,
                    List.of(urlError.get()), List.of(), startTime);
        }

        // 1. Local checks on the URL itself (HTTP, raw IP, @, nested subdomains).
        RuleScore ruleResult = rules.analyzeUrl(url);
        List<String> reasons = new ArrayList<>();
        reasons.add("URL rules: score " + ruleResult.score()
                + " -> " + ruleResult.level().label() + " risk");
        reasons.addAll(ruleResult.reasons());

        // 2. VirusTotal lookup.
        ApiResponse r = safeCheck(url);
        reasons.add(r.reason());

        Status status;
        RiskLevel risk = ruleResult.level();
        if (r.response() == ApiResponse.Response.LISTED) {
            status = Status.DANGER;
            risk = RiskLevel.HIGH;
        } else if (ruleResult.level() != RiskLevel.LOW) {
            status = Status.SUSPECT;
        } else if (r.response() == ApiResponse.Response.NOT_LISTED) {
            status = Status.SAFE;
        } else {
            status = Status.NOT_VERIFIED;
        }
        return result(item, status, risk, ruleResult.score(),
                reasons, r.threatTypes(), startTime);
    }

    private Result evaluateMessage(Item item, long startTime) {
        List<String> reasons = new ArrayList<>();

        RuleScore ruleResult = rules.analyzeText(item.content());
        reasons.add("Text rules: score " + ruleResult.score()
                + " -> " + ruleResult.level().label() + " risk");
        reasons.addAll(ruleResult.reasons());

        Status status;
        RiskLevel risk;
        switch (ruleResult.level()) {
            case HIGH -> {
                status = Status.SUSPECT;
                risk = RiskLevel.HIGH;
            }
            case MEDIUM -> {
                status = Status.SUSPECT;
                risk = RiskLevel.MEDIUM;
            }
            default -> {
                status = Status.LOW_RISK;
                risk = RiskLevel.LOW;
                reasons.add("No external verification for messages (Option A only); "
                        + "rules found nothing suspicious");
            }
        }

        return result(item, status, risk, ruleResult.score(), reasons, List.of(), startTime);
    }

    private ApiResponse safeCheck(String url) {
        try {
            ApiResponse r = lookup.checkUrl(url);
            return r != null ? r : ApiResponse.unavailable("Lookup returned no result");
        } catch (RuntimeException e) {
            return ApiResponse.unavailable("Lookup failed: " + e.getClass().getSimpleName());
        }
    }

    private static Result result(Item item, Status status, RiskLevel risk, int ruleScore,
                                           List<String> reasons, List<String> threatTypes, long startNanos) {
        long ms = (System.nanoTime() - startNanos) / 1_000_000;
        return new Result(item, status, risk, ruleScore, reasons, threatTypes, ms);
    }
}
