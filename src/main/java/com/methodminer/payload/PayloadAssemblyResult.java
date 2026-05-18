package com.methodminer.payload;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Immutable result of payload assembly — a ranked list of candidates with summary statistics.
 *
 * @param assembledAt    when this result was computed
 * @param totalCandidates total number of candidates
 * @param candidates     candidates sorted by descending score
 * @param countsByType   summary counts keyed by {@link PayloadCandidateType}
 */
public record PayloadAssemblyResult(
        Instant assembledAt,
        int totalCandidates,
        List<PayloadCandidate> candidates,
        Map<PayloadCandidateType, Integer> countsByType
) {
    /** An empty result with no candidates. */
    public static final PayloadAssemblyResult EMPTY = new PayloadAssemblyResult(
            Instant.EPOCH, 0, List.of(), Map.of());

    public PayloadAssemblyResult {
        assembledAt = Objects.requireNonNull(assembledAt, "assembledAt");
        candidates = List.copyOf(Objects.requireNonNullElse(candidates, List.of()));
        countsByType = Map.copyOf(Objects.requireNonNullElse(countsByType, Map.of()));
    }
}
