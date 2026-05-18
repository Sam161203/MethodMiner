package com.methodminer.core.model;

import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * A value-flow relationship inferred between two operations.
 */
public record Relationship(
        UUID id,
        UUID producerOperationId,
        UUID consumerOperationId,
        String entityPath,
        ConfidenceLevel confidence,
        List<UUID> observationIds,
        List<String> sampleFingerprints
) {
    public Relationship {
        id = Objects.requireNonNull(id, "id");
        producerOperationId = Objects.requireNonNull(producerOperationId, "producerOperationId");
        consumerOperationId = Objects.requireNonNull(consumerOperationId, "consumerOperationId");
        entityPath = Objects.requireNonNull(entityPath, "entityPath");
        confidence = Objects.requireNonNull(confidence, "confidence");
        observationIds = List.copyOf(Objects.requireNonNullElse(observationIds, List.of()));
        sampleFingerprints = List.copyOf(Objects.requireNonNullElse(sampleFingerprints, List.of()));
    }
}
