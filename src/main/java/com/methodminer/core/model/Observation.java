package com.methodminer.core.model;

import com.methodminer.protocol.ProtocolKind;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * A single normalized request/response fact with sanitized evidence.
 */
public record Observation(
        UUID id,
        ProtocolKind protocolKind,
        UUID serviceId,
        UUID endpointId,
        UUID operationId,
        Optional<UUID> sessionProfileId,
        Instant observedAt,
        Map<String, String> attributes,
        Optional<String> requestSummary,
        Optional<String> responseSummary
) {
    public Observation {
        id = Objects.requireNonNull(id, "id");
        protocolKind = Objects.requireNonNull(protocolKind, "protocolKind");
        serviceId = Objects.requireNonNull(serviceId, "serviceId");
        endpointId = Objects.requireNonNull(endpointId, "endpointId");
        operationId = Objects.requireNonNull(operationId, "operationId");
        sessionProfileId = Objects.requireNonNullElse(sessionProfileId, Optional.empty());
        observedAt = Objects.requireNonNull(observedAt, "observedAt");
        attributes = Map.copyOf(Objects.requireNonNullElse(attributes, Map.of()));
        requestSummary = Objects.requireNonNullElse(requestSummary, Optional.empty());
        responseSummary = Objects.requireNonNullElse(responseSummary, Optional.empty());
    }
}
