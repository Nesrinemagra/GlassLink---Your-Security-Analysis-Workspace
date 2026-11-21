package com.backend.service;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.backend.model.RiskLevel;

public final class RuleAnalyzer {

    static final int MEDIUM_SCORE = 3;
    static final int HIGH_SCORE = 6;
                                                                                  
    static final int URL_RULE_POINTS = 3;

    private record Rule(String name, int points, Pattern pattern) { }

    private static final List<Rule> KEYWORD_RULES = List.of(
            rule("Password request", 3,
                    "password", "passcode", "pin", "pin code", "otp", "one-time code", "verification code",
                    "security code", "login details", "card number", "cvv", "cvc", "bank details",
                    "verify your account", "confirm your identity", "confirm your account",
                    "social security", "mot de passe", "code secret", "code de vérification",
                    "numéro de carte", "identifiants"),
            rule("Only prizes and gifts", 3,

                    "you have won", "you've won", "winner", "prize", "lottery",
                    "free gift", "gift card", "claim your", "reward", "inheritance", "cash prize",
                    "vous avez gagné", "gagnant", "cadeau", "récompense"),
            rule("Account threat", 2,
                    "suspended", "suspension", "locked", "blocked", "deactivated", "disabled", "unusual activity",
                    "unauthorized", "unauthorised", "will be closed", "lose access", "compromised",
                    "suspendu", "bloqué", "désactivé", "activité inhabituelle"),
            rule("Urgency", 2,
                    "urgent", "urgently", "immediately", "act now", "verify now", "right away", "asap",
                    "as soon as possible", "within 24 hours", "within 24h", "last chance", "final notice",
                    "last warning", "expires today", "expire today", "immédiatement", "dernier avis",
                    "dans les 24 heures"),
            rule("Payment request", 2,
                    "pay now", "payment required", "wire transfer", "send money", "outstanding balance",
                    "overdue", "processing fee", "delivery fee", "customs fee", "bitcoin", "crypto",
                    "paiement", "frais de livraison", "virement"),
            rule("Common greetings", 1,
                    "dear customer", "dear user", "dear client", "valued customer", "dear account holder",
                    "cher client", "chère cliente")
    );

    private static final Set<String> SHORT_LINKS  = Set.of(
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "cutt.ly", "rb.gy", "shorturl.at");

    private static final Pattern IP_HOST = Pattern.compile("\\d{1,3}(\\.\\d{1,3}){3}");

    private final LinkFinder extractor;

    public RuleAnalyzer() {
        this(new LinkFinder());
    }

    public RuleAnalyzer(LinkFinder extractor) {
        this.extractor = extractor;
    }

    public RuleScore analyzeText(String text) {
        if (text == null || text.isBlank()) {
            return new RuleScore(0, RiskLevel.LOW, List.of());
        }

        int score = 0;
        List<String> reasons = new ArrayList<>();

        for (Rule rule : KEYWORD_RULES) {
            Set<String> foundWords = new LinkedHashSet<>();
            Matcher m = rule.pattern().matcher(text);
            while (m.find()) {
                foundWords.add(m.group().toLowerCase(Locale.ROOT));
            }
            if (!foundWords.isEmpty()) {
                score += rule.points();
                reasons.add(rule.name() + " (+" + rule.points() + "): " + String.join(", ", foundWords));
            }
        }

        List<String> urls = extractor.findLinks(text);
        if (urls.stream().anyMatch(RuleAnalyzer::hasIpHost)) {
            score += 2;
            reasons.add("Link points to a raw IP address (+2)");
        }
        if (urls.stream().anyMatch(RuleAnalyzer::isShortener)) {
            score += 1;
            reasons.add("Link uses a URL shortener that hides the destination (+1)");
        }

        if (mostlyUppercase(text)) {
            score += 1;
            reasons.add("Mostly CAPITAL letters (+1)");
        }
        if (text.contains("!!")) {
            score += 1;
            reasons.add("Repeated exclamation marks (+1)");
        }

        return new RuleScore(score, levelFor(score), reasons);
    }


                                                                            
    public RuleScore analyzeUrl(String url) {
        int score = 0;
        List<String> reasons = new ArrayList<>();

        URI uri;
        try {
            uri = new URI(url.trim());
        } catch (Exception e) {
            return new RuleScore(0, RiskLevel.LOW, List.of());
        }

        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        if (scheme.equals("http")) {
            score += URL_RULE_POINTS;
            reasons.add("Uses unencrypted HTTP (+" + URL_RULE_POINTS + ")");
        }

        String host = uri.getHost() == null ? "" : uri.getHost().toLowerCase(Locale.ROOT);
        if (IP_HOST.matcher(host).matches()) {
            score += URL_RULE_POINTS;
            reasons.add("Hostname is a raw IP address instead of a domain name (+" + URL_RULE_POINTS + ")");
        } else if (nestedSubdomains(host)) {
            score += URL_RULE_POINTS;
            reasons.add("Multiple nested subdomains and misleading domain structure (+" + URL_RULE_POINTS + ")");
        }

        String authority = uri.getRawAuthority() == null ? "" : uri.getRawAuthority();
        if (authority.contains("@")) {
            score += URL_RULE_POINTS;
            reasons.add("Contains @ symbol in URL authority section (+" + URL_RULE_POINTS + ")");
        }

        if (reasons.isEmpty()) {
            reasons.add("Valid " + scheme.toUpperCase(Locale.ROOT) + " protocol, standard domain structure");
        }
        return new RuleScore(score, levelFor(score), reasons);
    }

                                                                                  
    private static boolean nestedSubdomains(String host) {
        if (host.startsWith("www.")) host = host.substring(4);
        return host.split("\\.").length >= 4;
    }

    static RiskLevel levelFor(int score) {
        if (score >= HIGH_SCORE) return RiskLevel.HIGH;
        if (score >= MEDIUM_SCORE) return RiskLevel.MEDIUM;
        return RiskLevel.LOW;
    }

    private static Rule rule(String name, int points, String... phrases) {
        StringBuilder alternatives = new StringBuilder();
        for (String phrase : phrases) {
            if (!alternatives.isEmpty()) alternatives.append('|');
            alternatives.append(Pattern.quote(phrase));
        }

        Pattern p = Pattern.compile("(?<!\\w)(?:" + alternatives + ")(?!\\w)",
                Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE | Pattern.UNICODE_CHARACTER_CLASS);
        return new Rule(name, points, p);
    }

    private static String hostOf(String url) {
        try {
            String host = new URI(url).getHost();
            return host == null ? "" : host.toLowerCase(Locale.ROOT);
        } catch (Exception e) {
            return "";
        }
    }

    private static boolean hasIpHost(String url) {
        return IP_HOST.matcher(hostOf(url)).matches();
    }

    private static boolean isShortener(String url) {
        String host = hostOf(url);
        if (host.startsWith("www.")) host = host.substring(4);
        return SHORT_LINKS.contains(host);
    }

    private static boolean mostlyUppercase(String text) {
        int letters = 0, upper = 0;
        for (char c : text.toCharArray()) {
            if (Character.isLetter(c)) {
                letters++;
                if (Character.isUpperCase(c)) upper++;
            }
        }
        return letters >= 20 && upper * 10 >= letters * 6;
    }
}
