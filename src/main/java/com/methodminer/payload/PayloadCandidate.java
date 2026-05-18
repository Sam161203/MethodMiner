package com.methodminer.payload;

import com.methodminer.protocol.ProtocolKind;
import com.methodminer.risk.RiskConfidence;

import java.time.Instant;
import java.util.*;

/**
 * An immutable, ready-to-use payload candidate assembled from a risk signal and observed traffic.
 *
 * @param id                unique candidate identifier
 * @param timestamp         when this candidate was assembled
 * @param riskSignalId      ID of the originating risk signal
 * @param candidateType     classification type
 * @param protocolKind      protocol
 * @param host              target host
 * @param endpointPath      HTTP endpoint path
 * @param httpMethod        HTTP method (GET, POST, etc.)
 * @param operationName     API operation name
 * @param title             short human-readable title
 * @param summary           explanation of what this payload tests
 * @param rawBody           raw request body (JSON-RPC/GraphQL)
 * @param fullHttpRequest   complete HTTP request ready for Repeater
 * @param curlCommand       cURL command
 * @param variables         variable placeholders in the payload
 * @param requiredRole      session role needed to execute (e.g. "LOW_PRIV")
 * @param recommendedStep   what the tester should do with this payload
 * @param confidence        confidence level
 * @param score             inherited score from risk signal (0–100)
 */
public record PayloadCandidate(
        UUID id,
        Instant timestamp,
        UUID riskSignalId,
        PayloadCandidateType candidateType,
        ProtocolKind protocolKind,
        String host,
        String endpointPath,
        String httpMethod,
        String operationName,
        String title,
        String summary,
        String rawBody,
        String fullHttpRequest,
        String curlCommand,
        List<PayloadVariable> variables,
        String requiredRole,
        String recommendedStep,
        RiskConfidence confidence,
        int score
) {
    public PayloadCandidate {
        id = Objects.requireNonNull(id, "id");
        timestamp = Objects.requireNonNull(timestamp, "timestamp");
        riskSignalId = Objects.requireNonNull(riskSignalId, "riskSignalId");
        candidateType = Objects.requireNonNull(candidateType, "candidateType");
        protocolKind = Objects.requireNonNull(protocolKind, "protocolKind");
        host = Objects.requireNonNullElse(host, "");
        endpointPath = Objects.requireNonNullElse(endpointPath, "");
        httpMethod = Objects.requireNonNullElse(httpMethod, "POST");
        operationName = Objects.requireNonNull(operationName, "operationName");
        title = Objects.requireNonNull(title, "title");
        summary = Objects.requireNonNullElse(summary, "");
        rawBody = Objects.requireNonNullElse(rawBody, "");
        fullHttpRequest = Objects.requireNonNullElse(fullHttpRequest, "");
        curlCommand = Objects.requireNonNullElse(curlCommand, "");
        variables = List.copyOf(Objects.requireNonNullElse(variables, List.of()));
        requiredRole = Objects.requireNonNullElse(requiredRole, "LOW_PRIV");
        recommendedStep = Objects.requireNonNullElse(recommendedStep, "");
        confidence = Objects.requireNonNull(confidence, "confidence");
        score = Math.max(0, Math.min(100, score));
    }
}
