package com.threatdetector.service;

import com.threatdetector.model.Result;
import com.threatdetector.model.Item;
import com.threatdetector.model.ItemType;
import com.threatdetector.model.RiskLevel;
import com.threatdetector.model.Status;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ThreatEvaluatorTest {

    private final FakeThreatLookup fake = new FakeThreatLookup();
    private final Orchestrator evaluator = new Orchestrator(fake);

    private Result url(String content) {
        return evaluator.evaluate(Item.create(ItemType.URL, content));
    }

    private Result message(String content) {
        return evaluator.evaluate(Item.create(ItemType.MESSAGE, content));
    }

    @Test
    void emptyInputIsError() {
        assertEquals(Status.ERROR, url("").status());
        assertEquals(Status.ERROR, url("   ").status());
        assertEquals(Status.ERROR, message("").status());
        assertEquals(0, fake.calls.get(), "nothing should be sent to the API");
    }

    @Test
    void malformedUrlIsErrorAndNotSent() {
        assertEquals(Status.NOT_VERIFIED, url("htp:/broken url with spaces").status());
        assertEquals(Status.NOT_VERIFIED, url("www.no-scheme.com").status());
        assertEquals(Status.NOT_VERIFIED, url("ftp://files.example.com").status());
        assertEquals(Status.NOT_VERIFIED, url("https://").status());
        assertEquals(0, fake.calls.get());
    }

    @Test
    void listedUrlIsDanger() {
        Result r = url("http://evil.example.com/login");
        assertEquals(Status.DANGER, r.status());
        assertEquals("SOCIAL_ENGINEERING", r.threatTypes().get(0));
    }

    @Test
    void notListedUrlIsSafe() {
        assertEquals(Status.SAFE, url("https://www.google.com").status());
    }

    @Test
    void unavailableApiIsNotVerifiedNeverSafe() {
        assertEquals(Status.NOT_VERIFIED, url("https://down.example.com").status());
    }

    @Test
    void exceptionInLookupIsNotVerifiedNeverSafe() {
        Result r = url("https://crash.example.com");
        assertEquals(Status.NOT_VERIFIED, r.status());
        assertTrue(r.reasonText().contains("Lookup failed"));
    }

    @Test
    void nullFromLookupIsNotVerified() {
        assertEquals(Status.NOT_VERIFIED, url("https://null.example.com").status());
    }

    @Test
    void urlRiskLevelFollowsGoogleVerdict() {
        assertEquals(RiskLevel.HIGH, url("http://evil.example.com").riskLevel());
        assertEquals(RiskLevel.LOW, url("https://www.google.com").riskLevel());
        assertEquals(RiskLevel.LOW, url("https://down.example.com").riskLevel());
        assertEquals(0, url("https://www.google.com").ruleScore());
    }

    @Test
    void urlStructureRulesMatchExpectedDataset() {
        assertEquals(RiskLevel.LOW, url("https://www.example.edu/courses/cs302").riskLevel());
        assertEquals(RiskLevel.HIGH, url("http://192.168.1.50/portal/update").riskLevel());
        assertEquals(RiskLevel.HIGH, url("http://brand.account-security.example-portal.net/login").riskLevel());
        assertEquals(RiskLevel.HIGH, url("http://user:token@secure-portal.net/auth").riskLevel());
        assertEquals(RiskLevel.MEDIUM, url("http://www.example-news-blog.org/articles/guide.html").riskLevel());
        assertEquals(Status.NOT_VERIFIED, url("ht!tp://invalid_url_format.com/test").status());
    }

    @Test
    void suspensionNoticeWithIpLinkIsHigh() {
        Result r = message("Notice: Account verification required within 24 hours. Visit http://192.168.1.50/verify to prevent suspension.");
        assertEquals(RiskLevel.HIGH, r.riskLevel());
    }

    @Test
    void harmlessMessageWithoutLinksIsLowRiskNotSafe() {
        Result r = message("Hi, are we still meeting tomorrow?");
        assertEquals(Status.LOW_RISK, r.status());
        assertEquals(RiskLevel.LOW, r.riskLevel());
        assertEquals(0, fake.calls.get(), "no link, nothing sent to Google");
    }

    @Test
    void scamWordingWithoutLinksIsSuspect() {
        Result r = message("Your bank account is locked. Reply with your PIN and password immediately.");
        assertEquals(Status.SUSPECT, r.status());
        assertEquals(RiskLevel.HIGH, r.riskLevel());
        assertTrue(r.ruleScore() >= 6);
    }

    @Test
    void scamWordingWithCleanLinkIsStillSuspectAndDoesNotCallGoogle() {
        Result r = message("URGENT: account suspended, confirm your identity at https://good.com");
        assertEquals(Status.SUSPECT, r.status());
        assertEquals(RiskLevel.HIGH, r.riskLevel());
        assertEquals(0, fake.calls.get(), "messages never call Google (Option A only)");
    }

    @Test
    void messageWithLinkIsNeverSafeNorDanger() {

        Result r = message("Hey, photos from Saturday: http://evil.com/album");
        assertEquals(Status.LOW_RISK, r.status(), "harmless wording -> Low Risk, never Safe, never Danger");
        assertEquals(0, fake.calls.get());
    }

    @Test
    void messageWithUnverifiableLinkIsStillLowRisk() {
        Result r = message("Here is the report: https://down.example.com/report");
        assertEquals(Status.LOW_RISK, r.status());
        assertEquals(0, fake.calls.get());
    }

    @Test
    void messageWithIpLinkAddsRulePoints() {

        Result r = message("see http://192.168.10.5/login");
        assertEquals(Status.LOW_RISK, r.status());
        assertEquals(2, r.ruleScore());
        assertEquals(0, fake.calls.get());
    }

    @Test
    void allMessagesNeverCallGoogle() {
        message("Hi");
        message("URGENT: verify your password immediately at https://evil.com");
        message("You have won a prize, claim your reward at https://bit.ly/abc");
        message("See https://good.com and http://evil.com and https://down.com");
        assertEquals(0, fake.calls.get(), "Option A only: no network for messages, ever");
    }
}
