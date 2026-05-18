package com.methodminer.protocol;

import java.util.Objects;

/**
 * Detects which high-level API protocol an HTTP exchange belongs to.
 */
@FunctionalInterface
public interface ProtocolDetector {

    /**
     * Detect protocol kind and return a result with a confidence score and explanation.
     */
    DetectionResult detect(HttpExchange exchange);

    /**
     * Wrap a detector to null-check its return value.
     */
    static ProtocolDetector defensive(ProtocolDetector delegate) {
        Objects.requireNonNull(delegate, "delegate");
        return exchange -> Objects.requireNonNull(delegate.detect(exchange), "DetectionResult");
    }
}
