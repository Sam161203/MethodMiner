package com.methodminer.protocol;

import java.util.Map;
import java.util.Objects;

/**
 * Result of protocol detection for a single HTTP exchange.
 *
 * @param kind       detected protocol kind
 * @param confidence confidence score in the range [0.0, 1.0]
 * @param reason     short explanation for why the detector decided this
 * @param attributes optional, detector-specific attributes (e.g., method name hints)
 */
public record DetectionResult(
        ProtocolKind kind,
        double confidence,
        String reason,
        Map<String, String> attributes
) {
    public DetectionResult {
        kind = Objects.requireNonNull(kind, "kind");
        reason = Objects.requireNonNull(reason, "reason");
        attributes = Map.copyOf(Objects.requireNonNull(attributes, "attributes"));

        if (confidence < 0.0 || confidence > 1.0 || Double.isNaN(confidence)) {
            throw new IllegalArgumentException("confidence must be within [0.0, 1.0]");
        }
    }

    public static DetectionResult unknown(String reason) {
        return new DetectionResult(ProtocolKind.UNKNOWN, 0.0, reason, Map.of());
    }

    public static DetectionResult detected(ProtocolKind kind, double confidence, String reason) {
        return new DetectionResult(kind, confidence, reason, Map.of());
    }
}
