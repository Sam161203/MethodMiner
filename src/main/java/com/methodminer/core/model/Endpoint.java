package com.methodminer.core.model;

import com.methodminer.protocol.ProtocolKind;

import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * A concrete HTTP endpoint that carries a higher-level API protocol.
 */
public record Endpoint(
        UUID id,
        ProtocolKind protocolKind,
        String httpMethod,
        String path,
        Set<String> contentTypes,
        List<Operation> operations
) {
    public Endpoint {
        id = Objects.requireNonNull(id, "id");
        protocolKind = Objects.requireNonNull(protocolKind, "protocolKind");
        httpMethod = Objects.requireNonNull(httpMethod, "httpMethod");
        path = Objects.requireNonNull(path, "path");
        contentTypes = Set.copyOf(Objects.requireNonNullElse(contentTypes, Set.of()));
        operations = List.copyOf(Objects.requireNonNullElse(operations, List.of()));
    }
}
