package com.methodminer.protocol;

import java.util.List;
import java.util.Objects;

/**
 * Combines multiple {@link ProtocolDetector}s and returns the first non-UNKNOWN detection.
 */
public final class CompositeProtocolDetector implements ProtocolDetector {
    private final List<ProtocolDetector> detectors;

    public CompositeProtocolDetector(List<ProtocolDetector> detectors) {
        this.detectors = List.copyOf(Objects.requireNonNull(detectors, "detectors"));
    }

    @Override
    public DetectionResult detect(HttpExchange exchange) {
        Objects.requireNonNull(exchange, "exchange");

        for (ProtocolDetector detector : detectors) {
            if (detector == null) {
                continue;
            }

            DetectionResult result = detector.detect(exchange);
            if (result == null) {
                continue;
            }
            if (result.kind() != ProtocolKind.UNKNOWN) {
                return result;
            }
        }

        return DetectionResult.unknown("no-detector-matched");
    }
}
