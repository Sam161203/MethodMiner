package com.methodminer.core.events;

import com.methodminer.core.model.ApiSurface;

import java.util.Objects;

/**
 * Emitted after the in-memory {@link ApiSurface} snapshot has been updated.
 */
public record SurfaceChangedEvent(ApiSurface surface) {
    public SurfaceChangedEvent {
        surface = Objects.requireNonNull(surface, "surface");
    }
}
