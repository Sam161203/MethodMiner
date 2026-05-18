package com.methodminer.core.model;

import com.methodminer.protocol.ProtocolKind;

import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * A protocol-level operation (GraphQL query/mutation/subscription, JSON-RPC method, etc.).
 */
public record Operation(
        UUID id,
        ProtocolKind protocolKind,
        String name,
        OperationKind kind,
        List<Parameter> parameters,
        Optional<DataType> requestType,
        Optional<DataType> responseType
) {
    public Operation {
        id = Objects.requireNonNull(id, "id");
        protocolKind = Objects.requireNonNull(protocolKind, "protocolKind");
        name = Objects.requireNonNull(name, "name");
        kind = Objects.requireNonNull(kind, "kind");
        parameters = List.copyOf(Objects.requireNonNullElse(parameters, List.of()));
        requestType = Objects.requireNonNullElse(requestType, Optional.empty());
        responseType = Objects.requireNonNullElse(responseType, Optional.empty());
    }
}
