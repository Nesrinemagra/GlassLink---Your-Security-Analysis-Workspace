package com.backend.service;

import com.backend.model.RiskLevel;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MessageRuleScannerTest {

    private final RuleAnalyzer scanner = new RuleAnalyzer();

    @Test
    void normalMessageIsLow() {
        RuleScore r = scanner.analyzeText("Hi, are we still meeting tomorrow at 10?");
        assertEquals(0, r.score());
        assertEquals(RiskLevel.LOW, r.level());
        assertTrue(r.reasons().isEmpty());
    }

    @Test
    void credentialPlusThreatPlusUrgencyIsHigh() {
        RuleScore r = scanner.analyzeText("Your account is locked. Send your password immediately.");
        assertEquals(3 + 2 + 2, r.score());
        assertEquals(RiskLevel.HIGH, r.level());
    }

    @Test
    void prizeBaitAloneIsMedium() {
        RuleScore r = scanner.analyzeText("You have won a gift card, claim your prize today");
        assertEquals(3, r.score(), "a category counts once, however many of its words appear");
        assertEquals(RiskLevel.MEDIUM, r.level());
    }

    @Test
    void repeatingAWordDoesNotStackPoints() {
        RuleScore r = scanner.analyzeText("urgent urgent urgent urgent urgent");
        assertEquals(2, r.score());
    }

    @Test
    void wholeWordsOnly() {

        assertEquals(0, scanner.analyzeText("We went spinning, then ate hotpot").score());
    }

    @Test
    void caseInsensitive() {
        assertEquals(scanner.analyzeText("send your PASSWORD").score(), scanner.analyzeText("send your password").score());
    }

    @Test
    void frenchKeywordsWork() {
        RuleScore r = scanner.analyzeText("Votre compte est bloqué. Envoyez votre mot de passe immédiatement.");
        assertEquals(RiskLevel.HIGH, r.level());
    }

    @Test
    void ipLinkAndShortenerAddPoints() {
        assertEquals(2, scanner.analyzeText("see http://192.168.10.5/login").score());
        assertEquals(1, scanner.analyzeText("see https://bit.ly/abc123").score());
    }

    @Test
    void shoutingAndExclamationsAddPoints() {
        RuleScore r = scanner.analyzeText("THIS IS YOUR FINAL CHANCE TO ACT TODAY!!");
        assertTrue(r.reasons().stream().anyMatch(s -> s.contains("CAPITAL")));
        assertTrue(r.reasons().stream().anyMatch(s -> s.contains("exclamation")));
    }

    @Test
    void thresholds() {
        assertEquals(RiskLevel.LOW, RuleAnalyzer.levelFor(2));
        assertEquals(RiskLevel.MEDIUM, RuleAnalyzer.levelFor(3));
        assertEquals(RiskLevel.MEDIUM, RuleAnalyzer.levelFor(5));
        assertEquals(RiskLevel.HIGH, RuleAnalyzer.levelFor(6));
    }
}
