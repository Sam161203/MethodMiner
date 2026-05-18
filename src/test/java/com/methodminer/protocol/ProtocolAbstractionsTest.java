package com.methodminer.protocol;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ProtocolAbstractionsTest {

    @Test
    void detectionResultValidatesConfidenceRange() {
        assertThrows(IllegalArgumentException.class, () -> new DetectionResult(ProtocolKind.JSON_RPC, -0.1, "nope", Map.of()));
        assertThrows(IllegalArgumentException.class, () -> new DetectionResult(ProtocolKind.JSON_RPC, 1.1, "nope", Map.of()));
        assertThrows(IllegalArgumentException.class, () -> new DetectionResult(ProtocolKind.JSON_RPC, Double.NaN, "nope", Map.of()));
    }

    @Test
    void httpExchangeCopiesHeaderCollections() {
        List<String> values = new ArrayList<>(List.of("application/json"));
        Map<String, List<String>> headers = new HashMap<>();
        headers.put("Content-Type", values);

        HttpExchange exchange = new HttpExchange(
                UUID.randomUUID(),
                URI.create("https://example.test/jsonrpc"),
                "POST",
                headers,
                Optional.of("{}"),
                200,
                Map.of(),
                Optional.of("{}"),
                Instant.now()
        );

        values.add("text/plain");
        assertEquals(List.of("application/json"), exchange.requestHeaders().get("Content-Type"));
        assertThrows(UnsupportedOperationException.class, () -> exchange.requestHeaders().put("X-Test", List.of("1")));
        assertThrows(UnsupportedOperationException.class, () -> exchange.requestHeaders().get("Content-Type").add("x"));
    }
}
