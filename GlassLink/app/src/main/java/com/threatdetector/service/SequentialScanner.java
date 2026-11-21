package com.threatdetector.service;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import com.threatdetector.model.Result;
import com.threatdetector.model.Item;

public final class SequentialScanner {

    private final Orchestrator evaluator;

    public SequentialScanner(Orchestrator evaluator) {
        this.evaluator = Objects.requireNonNull(evaluator, "evaluator");
    }

    public Result evaluate(Item item) {
        return evaluator.evaluate(item);
    }

    public List<Result> evaluateAll(List<Item> items,
                                              java.util.function.BiConsumer<Integer, Integer> progress) {
        Objects.requireNonNull(items, "items");
        List<Result> results = new ArrayList<>(items.size());
        int total = items.size();
        int done = 0;
        for (Item item : items) {
            Result r = evaluator.evaluate(item);
            results.add(r);
            done++;
            if (progress != null) {
                try {
                    progress.accept(done, total);
                } catch (RuntimeException e) {

                    System.err.println("Progress callback error: " + e);
                }
            }
        }
        return results;
    }

    public List<Result> evaluateAll(List<Item> items) {
        return evaluateAll(items, null);
    }
}
