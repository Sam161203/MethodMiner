package com.methodminer.comparison;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Immutable result of a role comparison analysis across all observed operations.
 *
 * @param comparedAt          when this comparison was computed
 * @param totalSessions       total session profiles analyzed
 * @param totalOperations     total operations analyzed
 * @param operationCoverages  per-operation coverage details
 * @param countsByStatus      summary counts keyed by {@link CoverageStatus}
 */
public record RoleComparisonResult(
        Instant comparedAt,
        int totalSessions,
        int totalOperations,
        List<OperationRoleCoverage> operationCoverages,
        Map<CoverageStatus, Integer> countsByStatus
) {
    /** An empty result with no data. */
    public static final RoleComparisonResult EMPTY = new RoleComparisonResult(
            Instant.EPOCH, 0, 0, List.of(), Map.of());

    public RoleComparisonResult {
        comparedAt = Objects.requireNonNull(comparedAt, "comparedAt");
        operationCoverages = List.copyOf(Objects.requireNonNullElse(operationCoverages, List.of()));
        countsByStatus = Map.copyOf(Objects.requireNonNullElse(countsByStatus, Map.of()));
    }
}
