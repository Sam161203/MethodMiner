package com.methodminer.risk;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Immutable result of risk signal generation — a ranked list of signals with summary statistics.
 *
 * @param generatedAt      when this result was computed
 * @param totalSignals     total number of signals
 * @param signals          signals sorted by descending score
 * @param countsBySeverity summary counts keyed by {@link RiskSeverity}
 * @param countsByCategory summary counts keyed by {@link RiskSignalCategory}
 */
public record RiskSignalResult(
        Instant generatedAt,
        int totalSignals,
        List<RiskSignal> signals,
        Map<RiskSeverity, Integer> countsBySeverity,
        Map<RiskSignalCategory, Integer> countsByCategory
) {
    /** An empty result with no signals. */
    public static final RiskSignalResult EMPTY = new RiskSignalResult(
            Instant.EPOCH, 0, List.of(), Map.of(), Map.of());

    public RiskSignalResult {
        generatedAt = Objects.requireNonNull(generatedAt, "generatedAt");
        signals = List.copyOf(Objects.requireNonNullElse(signals, List.of()));
        countsBySeverity = Map.copyOf(Objects.requireNonNullElse(countsBySeverity, Map.of()));
        countsByCategory = Map.copyOf(Objects.requireNonNullElse(countsByCategory, Map.of()));
    }
}
