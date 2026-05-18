package com.methodminer.comparison;

import com.methodminer.protocol.ProtocolKind;

import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/**
 * Role coverage analysis for a single API operation.
 *
 * @param operationId       stable operation UUID
 * @param protocolKind      protocol type
 * @param host              target host
 * @param endpointPath      HTTP path
 * @param operationName     operation name
 * @param status            overall role coverage classification
 * @param adminSessionCount sessions labeled ADMIN that observed this operation
 * @param lowPrivSessionCount sessions labeled LOW_PRIV that observed this operation
 * @param unlabeledSessionCount sessions with no role label that observed this operation
 * @param parameterNames    all parameter names observed
 * @param parameterCoverage per-parameter coverage details
 */
public record OperationRoleCoverage(
        UUID operationId,
        ProtocolKind protocolKind,
        String host,
        String endpointPath,
        String operationName,
        CoverageStatus status,
        int adminSessionCount,
        int lowPrivSessionCount,
        int unlabeledSessionCount,
        Set<String> parameterNames,
        List<ParameterRoleCoverage> parameterCoverage
) {
    public OperationRoleCoverage {
        operationId = Objects.requireNonNull(operationId, "operationId");
        protocolKind = Objects.requireNonNull(protocolKind, "protocolKind");
        host = Objects.requireNonNullElse(host, "");
        endpointPath = Objects.requireNonNullElse(endpointPath, "");
        operationName = Objects.requireNonNull(operationName, "operationName");
        status = Objects.requireNonNull(status, "status");
        parameterNames = Set.copyOf(Objects.requireNonNullElse(parameterNames, Set.of()));
        parameterCoverage = List.copyOf(Objects.requireNonNullElse(parameterCoverage, List.of()));
    }
}
