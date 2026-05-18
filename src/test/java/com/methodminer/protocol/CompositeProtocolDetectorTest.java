package com.methodminer.protocol;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

class CompositeProtocolDetectorTest {

    @Test
    void returnsFirstNonUnknownDetection() {
        ProtocolDetector unknown = exchange -> DetectionResult.unknown("no");
        ProtocolDetector jsonRpc = exchange -> DetectionResult.detected(ProtocolKind.JSON_RPC, 0.9, "yes");

        CompositeProtocolDetector detector = new CompositeProtocolDetector(List.of(unknown, jsonRpc));
        DetectionResult result = detector.detect(sampleExchange());

        assertEquals(ProtocolKind.JSON_RPC, result.kind());
    }

    @Test
    void returnsUnknownIfNoneMatch() {
        ProtocolDetector unknown = exchange -> DetectionResult.unknown("no");

        CompositeProtocolDetector detector = new CompositeProtocolDetector(List.of(unknown));
        DetectionResult result = detector.detect(sampleExchange());

        assertEquals(ProtocolKind.UNKNOWN, result.kind());
    }

    private static HttpExchange sampleExchange() {
        return new HttpExchange(
                UUID.randomUUID(),
                URI.create("https://example.test/api"),
                "POST",
                Map.of("Content-Type", List.of("application/json")),
                Optional.of("{}"),
                200,
                Map.of(),
                Optional.empty(),
                Instant.now()
        );
    }
}
