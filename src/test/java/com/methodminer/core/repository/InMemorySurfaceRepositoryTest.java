package com.methodminer.core.repository;

import com.methodminer.core.model.ApiSurface;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class InMemorySurfaceRepositoryTest {

    @Test
    void snapshotReplaceAndClearWork() {
        InMemorySurfaceRepository repository = new InMemorySurfaceRepository("demo");

        ApiSurface initial = repository.snapshot();
        assertEquals("demo", initial.projectName());

        repository.replace(ApiSurface.create("other"));
        assertEquals("other", repository.snapshot().projectName());

        repository.clear();
        assertEquals("demo", repository.snapshot().projectName());
    }
}
