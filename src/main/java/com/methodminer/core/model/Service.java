package com.methodminer.core.model;

import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * A logical service boundary (typically host + base path) grouping endpoints.
 */
public record Service(
        UUID id,
        String name,
        String host,
        String basePath,
        List<Endpoint> endpoints
) {
    public Service {
        id = Objects.requireNonNull(id, "id");
        name = Objects.requireNonNull(name, "name");
        host = Objects.requireNonNull(host, "host");
        basePath = Objects.requireNonNull(basePath, "basePath");
        endpoints = List.copyOf(Objects.requireNonNullElse(endpoints, List.of()));
    }
}
