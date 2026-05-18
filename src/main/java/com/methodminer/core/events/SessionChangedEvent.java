package com.methodminer.core.events;

import com.methodminer.core.model.SessionProfile;

import java.util.Objects;

/**
 * Emitted when a {@link SessionProfile} is created or updated.
 */
public record SessionChangedEvent(SessionProfile sessionProfile) {
    public SessionChangedEvent {
        sessionProfile = Objects.requireNonNull(sessionProfile, "sessionProfile");
    }
}
