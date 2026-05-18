package com.methodminer.core.repository;

import com.methodminer.core.model.ApiSurface;

/**
 * Stores a single immutable {@link ApiSurface} snapshot.
 */
public interface SurfaceRepository {
    ApiSurface snapshot();

    void replace(ApiSurface surface);

    void clear();
}
