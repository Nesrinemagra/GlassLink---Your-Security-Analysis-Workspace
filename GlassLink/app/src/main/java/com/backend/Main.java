package com.backend;

import java.nio.file.Path;
import java.util.List;

import com.backend.config.AppConfig;
import com.backend.model.Result;
import com.backend.model.Item;
import com.backend.model.ItemType;
import com.backend.service.CsvReadException;
import com.backend.service.CsvResult;
import com.backend.service.CsvReader;
import com.backend.service.CsvRowError;
import com.backend.service.SequentialScanner;
import com.backend.service.Orchestrator;
import com.backend.service.VirusTotalChecker;

public final class Main {

    public static void main(String[] args) {

        AppConfig config = AppConfig.load(Path.of("config.properties"));

        if (!config.hasApiKey()) {
            System.out.println("WARNING: no API key configured (config.properties or VIRUSTOTAL_API_KEY).");
            System.out.println("         URLs will show as Not Verified - never Safe.\n");
        }

        Path csv = Path.of(args.length > 0 ? args[0] : "samples/project_test_dataset_simplified.csv");

        CsvResult parsed;
        try {
            parsed = new CsvReader().result(csv);
        } catch (CsvReadException e) {
            System.out.println("Cannot load batch: " + e.getMessage());
            return;
        }

        System.out.println("Loaded " + parsed.items().size() + " items from " + csv);
        if (parsed.hasErrors()) {
            System.out.println("Skipped " + parsed.errors().size() + " invalid rows:");
            for (CsvRowError error : parsed.errors()) {
                System.out.println("   " + error);
            }
        }
        System.out.println();

        List<Item> items = parsed.items();
        Orchestrator evaluator = new Orchestrator(new VirusTotalChecker(config));
        SequentialScanner service = new SequentialScanner(evaluator);

        long start = System.nanoTime();
        List<Result> results = service.evaluateAll(items, (done, total) ->
                System.out.printf("      progress %d/%d%n", done, total));
        long ms = (System.nanoTime() - start) / 1_000_000;

        System.out.println();
        System.out.println("==================================================================================================");
        System.out.printf("%-4s | %-10s | %-12s | %-8s | %-5s | %s%n",
                "ID", "Type", "Statut", "Risque", "Temps", "Aperçu du contenu / Raisons");
        System.out.println("--------------------------------------------------------------------------------------------------");

        for (Result r : results) {
            String type = r.item().type() == ItemType.URL ? "URL" : "MESSAGE";
            String apercu = shorten(r.item().content());

            System.out.printf("#%-3d | %-10s | %-12s | %-8s | %-3d ms | %s%n",
                    r.item().id(),
                    type,
                    r.status().label(),
                    r.riskLevel().label(),
                    r.durationMs(),
                    apercu);

            System.out.printf("     |            |              |          |        |   └─ %s%n", r.reasonText());
            System.out.println("--------------------------------------------------------------------------------------------------");
        }

        int safe = 0, danger = 0, suspect = 0, lowRisk = 0, notVerified = 0, error = 0;
        for (Result r : results) {
            switch (r.status()) {
                case SAFE -> safe++;
                case DANGER -> danger++;
                case SUSPECT -> suspect++;
                case LOW_RISK -> lowRisk++;
                case ERROR -> error++;
                default -> notVerified++;
            }
        }

        System.out.println("\n📊 RESUME DE L'ANALYSE :");
        System.out.println("   [SAFE]         : " + safe);
        System.out.println("   [DANGER]       : " + danger);
        System.out.println("   [SUSPECT]      : " + suspect);
        System.out.println("   [LOW RISK]     : " + lowRisk);
        System.out.println("   [NOT VERIFIED] : " + notVerified);
        System.out.println("   [ERROR]        : " + error);
        System.out.println("==================================================================================================");
        System.out.println("Temps total : " + ms + " ms");
    }

    private static String shorten(String s) {
        return s.length() <= 60 ? s : s.substring(0, 57) + "...";
    }
}
