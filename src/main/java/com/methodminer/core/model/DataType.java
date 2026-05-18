package com.methodminer.core.model;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Protocol-agnostic structural data type inferred from observed traffic.
 */
public record DataType(
        UUID id,
        String name,
        DataTypeKind kind,
        ConfidenceLevel confidence,
        Map<String, DataType> fields,
        Optional<DataType> elementType,
        List<DataType> variants,
        List<String> enumValues,
        List<String> examples
) {
    public DataType {
        id = Objects.requireNonNull(id, "id");
        name = Objects.requireNonNull(name, "name");
        kind = Objects.requireNonNull(kind, "kind");
        confidence = Objects.requireNonNull(confidence, "confidence");
        fields = Map.copyOf(Objects.requireNonNullElse(fields, Map.of()));
        elementType = Objects.requireNonNullElse(elementType, Optional.empty());
        variants = List.copyOf(Objects.requireNonNullElse(variants, List.of()));
        enumValues = List.copyOf(Objects.requireNonNullElse(enumValues, List.of()));
        examples = List.copyOf(Objects.requireNonNullElse(examples, List.of()));
    }

    public static DataType unknown(String name) {
        return new DataType(
                UUID.randomUUID(),
                name,
                DataTypeKind.UNKNOWN,
                ConfidenceLevel.UNKNOWN,
                Map.of(),
                Optional.empty(),
                List.of(),
                List.of(),
                List.of()
        );
    }
}
