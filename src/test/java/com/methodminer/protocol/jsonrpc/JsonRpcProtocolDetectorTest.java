package com.methodminer.protocol.jsonrpc;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.methodminer.protocol.DetectionResult;
import com.methodminer.protocol.HttpExchange;
import com.methodminer.protocol.ProtocolKind;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

class JsonRpcProtocolDetectorTest {

    @Test
    void detectsJsonRpcWithJsonrpc2() {
        JsonRpcProtocolDetector detector = new JsonRpcProtocolDetector(new ObjectMapper());
        HttpExchange exchange = exchangeWithBody("{\"jsonrpc\":\"2.0\",\"method\":\"user.get\",\"params\":{\"id\":1},\"id\":1}");

        DetectionResult result = detector.detect(exchange);

        assertEquals(ProtocolKind.JSON_RPC, result.kind());
        assertEquals("user.get", result.attributes().get("methodName"));
        assertEquals("user", result.attributes().get("namespace"));
        assertEquals("get", result.attributes().get("methodSimpleName"));
        assertEquals("named", result.attributes().get("paramsMode"));
        assertEquals("integer", result.attributes().get("idType"));
        assertEquals("false", result.attributes().get("notification"));
        assertEquals("false", result.attributes().get("batch"));
    }

    @Test
    void detectsJsonRpcWhenJsonrpcMissingWithLowerConfidence() {
        JsonRpcProtocolDetector detector = new JsonRpcProtocolDetector(new ObjectMapper());
        HttpExchange exchange = exchangeWithBody("{\"method\":\"ping\",\"id\":\"1\"}");

        DetectionResult result = detector.detect(exchange);

        assertEquals(ProtocolKind.JSON_RPC, result.kind());
        assertEquals("ping", result.attributes().get("methodName"));
    }

    @Test
    void rejectsMismatchedJsonrpcVersion() {
        JsonRpcProtocolDetector detector = new JsonRpcProtocolDetector(new ObjectMapper());
        HttpExchange exchange = exchangeWithBody("{\"jsonrpc\":\"1.0\",\"method\":\"ping\",\"id\":1}");

        DetectionResult result = detector.detect(exchange);

        assertEquals(ProtocolKind.UNKNOWN, result.kind());
    }

    @Test
    void detectsBatchRequests() {
        JsonRpcProtocolDetector detector = new JsonRpcProtocolDetector(new ObjectMapper());
        HttpExchange exchange = exchangeWithBody("[{\"jsonrpc\":\"2.0\",\"method\":\"a\",\"id\":1},{\"jsonrpc\":\"2.0\",\"method\":\"b\",\"id\":2}]");

        DetectionResult result = detector.detect(exchange);

        assertEquals(ProtocolKind.JSON_RPC, result.kind());
        assertEquals("true", result.attributes().get("batch"));
        assertEquals("a", result.attributes().get("methodName"));
    }

    private static HttpExchange exchangeWithBody(String body) {
        return new HttpExchange(
                UUID.randomUUID(),
                URI.create("https://example.test/rpc"),
                "POST",
                Map.of("Content-Type", List.of("application/json")),
                Optional.ofNullable(body),
                200,
                Map.of("Content-Type", List.of("application/json")),
                Optional.empty(),
                Instant.parse("2026-01-01T00:00:00Z")
        );
    }
}
