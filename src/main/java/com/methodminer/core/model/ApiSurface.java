package com.methodminer.core.model;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * Protocol-agnostic snapshot of discovered API surface for a single Burp project.
 *
 * <p>Note: {@code riskSignals}, {@code recommendations}, and {@code attackChains} are reserved
 * for future embedded analysis. Currently, risk analysis is performed by the
 * {@code RiskSignalGenerator} and {@code PayloadAssembler} services, which read from
 * the repository directly. These fields remain in the record to preserve the domain model
 * schema and avoid broad refactoring; they are always {@code List.of()} at runtime.
 */
public record ApiSurface(
        UUID id,
        String projectName,
        List<Service> services,
    List<Observation> observations,
        List<SessionProfile> sessionProfiles,
        List<Relationship> relationships,
        List<RiskSignal> riskSignals,
        List<AttackRecommendation> recommendations,
        List<AttackChain> attackChains,
        Instant createdAt,
        Instant updatedAt
) {
    public ApiSurface {
        id = Objects.requireNonNull(id, "id");
        projectName = Objects.requireNonNull(projectName, "projectName");
        services = List.copyOf(Objects.requireNonNullElse(services, List.of()));
        observations = List.copyOf(Objects.requireNonNullElse(observations, List.of()));
        sessionProfiles = List.copyOf(Objects.requireNonNullElse(sessionProfiles, List.of()));
        relationships = List.copyOf(Objects.requireNonNullElse(relationships, List.of()));
        riskSignals = List.copyOf(Objects.requireNonNullElse(riskSignals, List.of()));
        recommendations = List.copyOf(Objects.requireNonNullElse(recommendations, List.of()));
        attackChains = List.copyOf(Objects.requireNonNullElse(attackChains, List.of()));
        createdAt = Objects.requireNonNull(createdAt, "createdAt");
        updatedAt = Objects.requireNonNull(updatedAt, "updatedAt");

        if (updatedAt.isBefore(createdAt)) {
            throw new IllegalArgumentException("updatedAt must be >= createdAt");
        }
    }

    public static ApiSurface create(String projectName) {
        Instant now = Instant.now();
        return new ApiSurface(
                UUID.randomUUID(),
                projectName,
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                now,
                now
        );
    }
}
