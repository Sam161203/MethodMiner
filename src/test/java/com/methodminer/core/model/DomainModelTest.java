package com.methodminer.core.model;

import com.methodminer.protocol.ProtocolKind;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class DomainModelTest {

    @Test
    void copiesCollectionsToRemainImmutable() {
        List<String> examples = new ArrayList<>(List.of("x-1"));

        Parameter parameter = new Parameter(
                UUID.randomUUID(),
                "id",
                "$.id",
                ParameterSource.BODY,
                true,
                DataType.unknown("string"),
                false,
                examples
        );

        examples.add("x-2");
        assertEquals(List.of("x-1"), parameter.examples());
        assertThrows(UnsupportedOperationException.class, () -> parameter.examples().add("x-3"));
    }

    @Test
    void apiSurfaceRejectsBackwardsTimestamps() {
        Instant createdAt = Instant.now();
        Instant updatedAt = createdAt.minusSeconds(1);

        assertThrows(IllegalArgumentException.class, () -> new ApiSurface(
                UUID.randomUUID(),
                "demo",
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                List.of(),
                createdAt,
                updatedAt
        ));
    }

    @Test
    void observationCopiesAttributeMap() {
        Map<String, String> attributes = new HashMap<>();
        attributes.put("k", "v");

        Observation observation = new Observation(
                UUID.randomUUID(),
                ProtocolKind.JSON_RPC,
                UUID.randomUUID(),
                UUID.randomUUID(),
                UUID.randomUUID(),
                Optional.empty(),
                Instant.now(),
                attributes,
                Optional.of("request"),
                Optional.of("response")
        );

        attributes.put("k2", "v2");
        assertEquals(Map.of("k", "v"), observation.attributes());
        assertThrows(UnsupportedOperationException.class, () -> observation.attributes().put("k3", "v3"));
    }
}
