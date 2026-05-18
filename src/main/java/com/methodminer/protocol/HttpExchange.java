package com.methodminer.protocol;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Burp-agnostic representation of a captured HTTP request/response pair.
 *
 * <p>This is intentionally a minimal transport object for protocol detection/normalization.
 * Future iterations may replace bodies with sanitized excerpts or references.
 */
public record HttpExchange(
        UUID id,
        URI uri,
        String method,
        Map<String, List<String>> requestHeaders,
        Optional<String> requestBody,
        int responseStatusCode,
        Map<String, List<String>> responseHeaders,
        Optional<String> responseBody,
        Instant observedAt
) {
    public HttpExchange {
        id = Objects.requireNonNull(id, "id");
        uri = Objects.requireNonNull(uri, "uri");
        method = Objects.requireNonNull(method, "method");
        requestHeaders = immutableHeaders(Objects.requireNonNull(requestHeaders, "requestHeaders"));
        requestBody = Objects.requireNonNull(requestBody, "requestBody");
        responseHeaders = immutableHeaders(Objects.requireNonNull(responseHeaders, "responseHeaders"));
        responseBody = Objects.requireNonNull(responseBody, "responseBody");
        observedAt = Objects.requireNonNull(observedAt, "observedAt");
    }

    private static Map<String, List<String>> immutableHeaders(Map<String, List<String>> headers) {
        if (headers.isEmpty()) {
            return Map.of();
        }
        return headers.entrySet().stream()
                .collect(Collectors.toUnmodifiableMap(
                        e -> Objects.requireNonNull(e.getKey(), "headerName"),
                        e -> List.copyOf(Objects.requireNonNullElse(e.getValue(), List.of()))
                ));
    }
}
