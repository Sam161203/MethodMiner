package com.methodminer.core.model;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * A prioritized, evidence-backed recommendation for manual testing.
 */
public record AttackRecommendation(
        UUID id,
        String title,
        String vulnerabilityType,
        Severity severity,
        ConfidenceLevel confidence,
        List<UUID> operationIds,
        List<UUID> evidenceObservationIds,
        Optional<String> payload,
        Optional<UUID> attackChainId,
        Instant createdAt
) {
    public AttackRecommendation {
        id = Objects.requireNonNull(id, "id");
        title = Objects.requireNonNull(title, "title");
        vulnerabilityType = Objects.requireNonNull(vulnerabilityType, "vulnerabilityType");
        severity = Objects.requireNonNull(severity, "severity");
        confidence = Objects.requireNonNull(confidence, "confidence");
        operationIds = List.copyOf(Objects.requireNonNullElse(operationIds, List.of()));
        evidenceObservationIds = List.copyOf(Objects.requireNonNullElse(evidenceObservationIds, List.of()));
        payload = Objects.requireNonNullElse(payload, Optional.empty());
        attackChainId = Objects.requireNonNullElse(attackChainId, Optional.empty());
        createdAt = Objects.requireNonNull(createdAt, "createdAt");
    }
}
