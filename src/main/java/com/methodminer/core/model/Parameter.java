package com.methodminer.core.model;

import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * A parameter accepted by an {@link Operation}.
 */
public record Parameter(
        UUID id,
        String name,
        String path,
        ParameterSource source,
        boolean required,
        DataType dataType,
        boolean sensitive,
        List<String> examples
) {
    public Parameter {
        id = Objects.requireNonNull(id, "id");
        name = Objects.requireNonNull(name, "name");
        path = Objects.requireNonNull(path, "path");
        source = Objects.requireNonNull(source, "source");
        dataType = Objects.requireNonNull(dataType, "dataType");
        examples = List.copyOf(Objects.requireNonNullElse(examples, List.of()));
    }
}
