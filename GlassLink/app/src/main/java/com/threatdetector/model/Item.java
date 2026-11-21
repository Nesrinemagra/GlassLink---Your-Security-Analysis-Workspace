package com.threatdetector.model;

import java.util.Objects;

public record Item(int id, ItemType type, String content) {

    private static int nextId = 1;

    public Item {
        Objects.requireNonNull(type, "type");
        content = content == null ? "" : content;
    }

    public static Item create(ItemType type, String content) {
        return new Item(nextId++, type, content);
    }
}
