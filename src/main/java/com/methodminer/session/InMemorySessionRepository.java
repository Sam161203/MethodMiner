package com.methodminer.session;

import com.methodminer.core.model.ConfidenceLevel;
import com.methodminer.core.model.Role;
import com.methodminer.core.model.SessionProfile;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe, in-memory implementation of {@link SessionRepository}.
 *
 * <p>Session profiles are keyed by a stable UUID derived from the fingerprint's
 * host + auth mechanism + token hash. Multiple observations with the same
 * fingerprint will upsert the same profile (incrementing request count).
 */
public final class InMemorySessionRepository implements SessionRepository {

    private final ConcurrentHashMap<UUID, SessionProfile> profiles = new ConcurrentHashMap<>();

    @Override
    public SessionProfile upsert(SessionFingerprint fingerprint, Instant observedAt) {
        Objects.requireNonNull(fingerprint, "fingerprint");
        Objects.requireNonNull(observedAt, "observedAt");

        UUID id = stableId(fingerprint);

        return profiles.compute(id, (key, existing) -> {
            if (existing != null) {
                return existing.withObservation(observedAt);
            }

            // Determine initial confidence
            ConfidenceLevel confidence;
            if (!fingerprint.tokenHash().isBlank() && !fingerprint.username().isBlank()) {
                confidence = ConfidenceLevel.HIGH;
            } else if (!fingerprint.tokenHash().isBlank() || !fingerprint.username().isBlank()) {
                confidence = ConfidenceLevel.MEDIUM;
            } else if (!fingerprint.cookieNames().isEmpty()) {
                confidence = ConfidenceLevel.LOW;
            } else {
                confidence = ConfidenceLevel.UNKNOWN;
            }

            return new SessionProfile(
                    id,
                    fingerprint.host(),
                    fingerprint.username(),
                    fingerprint.database(),
                    Role.UNKNOWN,
                    fingerprint.authMechanism().isBlank()
                            ? Set.of()
                            : Set.of(fingerprint.authMechanism()),
                    fingerprint.cookieNames(),
                    fingerprint.authHeaderNames(),
                    1,
                    observedAt,
                    observedAt,
                    confidence,
                    fingerprint.metadata(),
                    fingerprint.tokenHash().isBlank()
                            ? Set.of()
                            : Set.of(fingerprint.tokenHash())
            );
        });
    }

    @Override
    public Optional<SessionProfile> findById(UUID id) {
        if (id == null) return Optional.empty();
        return Optional.ofNullable(profiles.get(id));
    }

    @Override
    public List<SessionProfile> snapshot() {
        List<SessionProfile> list = new ArrayList<>(profiles.values());
        list.sort(Comparator.comparing(SessionProfile::lastSeen).reversed());
        return List.copyOf(list);
    }

    @Override
    public boolean setRole(UUID sessionId, Role role) {
        if (sessionId == null || role == null) return false;
        SessionProfile updated = profiles.computeIfPresent(sessionId, (key, existing) -> {
            if (existing.role() == role) return existing;
            return existing.withRole(role);
        });
        return updated != null && updated.role() == role;
    }

    @Override
    public void clear() {
        profiles.clear();
    }

    /** Compute a stable UUID from the fingerprint's key fields. */
    private static UUID stableId(SessionFingerprint fp) {
        String key = "session:" + fp.host() + "|" + fp.authMechanism() + "|" + fp.tokenHash();
        return UUID.nameUUIDFromBytes(key.getBytes(StandardCharsets.UTF_8));
    }
}
