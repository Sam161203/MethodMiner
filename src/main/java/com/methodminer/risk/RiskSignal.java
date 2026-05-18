package com.methodminer.risk;

import com.methodminer.comparison.CoverageStatus;
import com.methodminer.protocol.ProtocolKind;

import java.time.Instant;
import java.util.*;

/**
 * An immutable risk signal representing a potential authorization or privilege-escalation
 * test opportunity discovered through passive role comparison.
 *
 * @param id                unique signal identifier
 * @param timestamp         when this signal was generated
 * @param category          classification category
 * @param title             short human-readable title
 * @param summary           detailed explanation of why this signal was generated
 * @param protocolKind      protocol type
 * @param host              target host
 * @param endpointPath      HTTP endpoint path
 * @param operationName     API operation name
 * @param severity          severity level
 * @param confidence        confidence level
 * @param score             deterministic score (0–100)
 * @param evidenceRefs      references to supporting evidence
 * @param recommendedAction suggested next testing step
 * @param parameters        supporting parameter names
 * @param coverageStatus    role coverage classification from comparison engine
 */
public record RiskSignal(
        UUID id,
        Instant timestamp,
        RiskSignalCategory category,
        String title,
        String summary,
        ProtocolKind protocolKind,
        String host,
        String endpointPath,
        String operationName,
        RiskSeverity severity,
        RiskConfidence confidence,
        int score,
        List<String> evidenceRefs,
        String recommendedAction,
        Set<String> parameters,
        CoverageStatus coverageStatus
) {
    public RiskSignal {
        id = Objects.requireNonNull(id, "id");
        timestamp = Objects.requireNonNull(timestamp, "timestamp");
        category = Objects.requireNonNull(category, "category");
        title = Objects.requireNonNull(title, "title");
        summary = Objects.requireNonNullElse(summary, "");
        protocolKind = Objects.requireNonNull(protocolKind, "protocolKind");
        host = Objects.requireNonNullElse(host, "");
        endpointPath = Objects.requireNonNullElse(endpointPath, "");
        operationName = Objects.requireNonNull(operationName, "operationName");
        severity = Objects.requireNonNull(severity, "severity");
        confidence = Objects.requireNonNull(confidence, "confidence");
        score = Math.max(0, Math.min(100, score));
        evidenceRefs = List.copyOf(Objects.requireNonNullElse(evidenceRefs, List.of()));
        recommendedAction = Objects.requireNonNullElse(recommendedAction, "");
        parameters = Set.copyOf(Objects.requireNonNullElse(parameters, Set.of()));
        coverageStatus = Objects.requireNonNull(coverageStatus, "coverageStatus");
    }
}
