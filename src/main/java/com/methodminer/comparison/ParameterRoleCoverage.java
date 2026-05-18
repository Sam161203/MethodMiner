package com.methodminer.comparison;

import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Role coverage detail for a single parameter within an operation.
 *
 * @param name           parameter name
 * @param status         role coverage classification
 * @param typesByRole    inferred type strings keyed by role label (e.g. "ADMIN" → "integer")
 */
public record ParameterRoleCoverage(
        String name,
        CoverageStatus status,
        Map<String, Set<String>> typesByRole
) {
    public ParameterRoleCoverage {
        name = Objects.requireNonNull(name, "name");
        status = Objects.requireNonNull(status, "status");
        typesByRole = Map.copyOf(Objects.requireNonNullElse(typesByRole, Map.of()));
    }
}
