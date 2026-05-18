package com.methodminer.core.model;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Atomic signal contributing to a risk score with evidence references.
 */
public record RiskSignal(
        UUID id,
        UUID operationId,
        String type,
        int score,
        ConfidenceLevel confidence,
        Optional<UUID> observationId,
        String summary,
        Map<String, String> attributes
) {
    public RiskSignal {
        id = Objects.requireNonNull(id, "id");
        operationId = Objects.requireNonNull(operationId, "operationId");
        type = Objects.requireNonNull(type, "type");
        confidence = Objects.requireNonNull(confidence, "confidence");
        observationId = Objects.requireNonNullElse(observationId, Optional.empty());
        summary = Objects.requireNonNull(summary, "summary");
        attributes = Map.copyOf(Objects.requireNonNullElse(attributes, Map.of()));
    }
}
