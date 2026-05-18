package com.methodminer.core.repository;

import com.methodminer.core.model.ApiSurface;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Thread-safe in-memory {@link SurfaceRepository}.
 */
public final class InMemorySurfaceRepository implements SurfaceRepository {
    private final String projectName;
    private final AtomicReference<ApiSurface> ref;

    public InMemorySurfaceRepository(String projectName) {
        this.projectName = Objects.requireNonNull(projectName, "projectName");
        this.ref = new AtomicReference<>(ApiSurface.create(projectName));
    }

    public InMemorySurfaceRepository(ApiSurface initialSurface) {
        ApiSurface initial = Objects.requireNonNull(initialSurface, "initialSurface");
        this.projectName = initial.projectName();
        this.ref = new AtomicReference<>(initial);
    }

    @Override
    public ApiSurface snapshot() {
        return ref.get();
    }

    @Override
    public void replace(ApiSurface surface) {
        ref.set(Objects.requireNonNull(surface, "surface"));
    }

    @Override
    public void clear() {
        ref.set(ApiSurface.create(projectName));
    }
}
