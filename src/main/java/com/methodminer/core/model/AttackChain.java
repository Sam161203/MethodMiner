package com.methodminer.core.model;

import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * Ordered operations linked by relationships and evidence.
 */
public record AttackChain(
        UUID id,
        String name,
        List<UUID> operationIds,
        List<UUID> relationshipIds,
        List<UUID> evidenceObservationIds,
        List<UUID> sessionProfileIds
) {
    public AttackChain {
        id = Objects.requireNonNull(id, "id");
        name = Objects.requireNonNull(name, "name");
        operationIds = List.copyOf(Objects.requireNonNullElse(operationIds, List.of()));
        relationshipIds = List.copyOf(Objects.requireNonNullElse(relationshipIds, List.of()));
        evidenceObservationIds = List.copyOf(Objects.requireNonNullElse(evidenceObservationIds, List.of()));
        sessionProfileIds = List.copyOf(Objects.requireNonNullElse(sessionProfileIds, List.of()));
    }
}
