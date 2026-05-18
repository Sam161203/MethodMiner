package com.methodminer.session;

import com.methodminer.core.model.Role;
import com.methodminer.core.model.SessionProfile;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository for discovered session profiles.
 */
public interface SessionRepository {

    /**
     * Create or update a session profile based on observed authentication material.
     *
     * <p>If a profile with a matching fingerprint hash already exists, it will be updated
     * (request count incremented, lastSeen updated). Otherwise a new profile is created.
     *
     * @param fingerprint the authentication fingerprint from the current exchange
     * @param observedAt  the timestamp of the observation
     * @return the created or updated session profile
     */
    SessionProfile upsert(SessionFingerprint fingerprint, Instant observedAt);

    /** Find a session profile by its stable ID. */
    Optional<SessionProfile> findById(UUID id);

    /** Return a snapshot of all known session profiles, ordered by lastSeen descending. */
    List<SessionProfile> snapshot();

    /**
     * Set the role for a session profile.
     *
     * @return true if the role was changed
     */
    boolean setRole(UUID sessionId, Role role);

    /** Remove all session profiles. */
    void clear();
}
