package com.methodminer.core.model;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * A named session profile derived from observed authentication material.
 *
 * <p>Raw auth values should remain memory-only; persisted data should use fingerprints.
 */
public record SessionProfile(
        UUID id,
        String host,
        String username,
        String database,
        Role role,
        Set<String> authMechanisms,
        Set<String> cookieNames,
        Set<String> headerNames,
        int requestCount,
        Instant firstSeen,
        Instant lastSeen,
        ConfidenceLevel confidence,
        Map<String, String> metadata,
        Set<String> authFingerprints
) {
    public SessionProfile {
        id = Objects.requireNonNull(id, "id");
        host = Objects.requireNonNullElse(host, "");
        username = Objects.requireNonNullElse(username, "");
        database = Objects.requireNonNullElse(database, "");
        role = Objects.requireNonNull(role, "role");
        authMechanisms = Set.copyOf(Objects.requireNonNullElse(authMechanisms, Set.of()));
        cookieNames = Set.copyOf(Objects.requireNonNullElse(cookieNames, Set.of()));
        headerNames = Set.copyOf(Objects.requireNonNullElse(headerNames, Set.of()));
        firstSeen = Objects.requireNonNull(firstSeen, "firstSeen");
        lastSeen = Objects.requireNonNull(lastSeen, "lastSeen");
        confidence = Objects.requireNonNull(confidence, "confidence");
        metadata = Map.copyOf(Objects.requireNonNullElse(metadata, Map.of()));
        authFingerprints = Set.copyOf(Objects.requireNonNullElse(authFingerprints, Set.of()));

        if (lastSeen.isBefore(firstSeen)) {
            throw new IllegalArgumentException("lastSeen must be >= firstSeen");
        }
    }

    /** Create an updated copy with incremented request count and new lastSeen. */
    public SessionProfile withObservation(Instant observedAt) {
        Instant newLastSeen = observedAt.isAfter(lastSeen) ? observedAt : lastSeen;
        return new SessionProfile(id, host, username, database, role,
                authMechanisms, cookieNames, headerNames,
                requestCount + 1, firstSeen, newLastSeen,
                confidence, metadata, authFingerprints);
    }

    /** Create an updated copy with a new role. */
    public SessionProfile withRole(Role newRole) {
        return new SessionProfile(id, host, username, database, newRole,
                authMechanisms, cookieNames, headerNames,
                requestCount, firstSeen, lastSeen,
                confidence, metadata, authFingerprints);
    }
}
