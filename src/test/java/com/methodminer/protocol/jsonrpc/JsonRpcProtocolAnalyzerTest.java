package com.methodminer.protocol.jsonrpc;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.methodminer.core.model.DataTypeKind;
import com.methodminer.core.model.ParameterSource;
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
import static org.junit.jupiter.api.Assertions.assertTrue;

class JsonRpcProtocolAnalyzerTest {

    @Test
    void analyzesSingleCallWithNamedParamsAndResult() {
        JsonRpcProtocolAnalyzer analyzer = new JsonRpcProtocolAnalyzer(new ObjectMapper());

        HttpExchange exchange = new HttpExchange(
                UUID.randomUUID(),
                URI.create("https://example.test/rpc"),
                "POST",
                Map.of("Content-Type", List.of("application/json")),
                Optional.of("{\"jsonrpc\":\"2.0\",\"method\":\"user.get\",\"params\":{\"id\":123},\"id\":1}"),
                200,
                Map.of("Content-Type", List.of("application/json")),
                Optional.of("{\"jsonrpc\":\"2.0\",\"result\":{\"name\":\"Alice\",\"age\":30},\"id\":1}"),
                Instant.parse("2026-01-01T00:00:00Z")
        );

        List<JsonRpcProtocolAnalyzer.AnalysisResult> results = analyzer.analyze(
                exchange,
                DetectionResult.detected(ProtocolKind.JSON_RPC, 1.0, "unit")
        );

        assertEquals(1, results.size());

        JsonRpcProtocolAnalyzer.AnalysisResult result = results.get(0);
        assertEquals("example.test", result.service().host());
        assertEquals("POST", result.endpoint().httpMethod());
        assertEquals("/rpc", result.endpoint().path());

        assertEquals("user.get", result.operation().name());
        assertEquals(1, result.operation().parameters().size());
        assertEquals("id", result.operation().parameters().get(0).name());
        assertEquals(ParameterSource.JSON_RPC_PARAM, result.operation().parameters().get(0).source());

        assertTrue(result.operation().requestType().isPresent());
        assertEquals(DataTypeKind.OBJECT, result.operation().requestType().get().kind());
        assertTrue(result.operation().requestType().get().fields().containsKey("id"));

        assertTrue(result.operation().responseType().isPresent());
        assertEquals(DataTypeKind.OBJECT, result.operation().responseType().get().kind());
        assertTrue(result.operation().responseType().get().fields().containsKey("name"));
        assertTrue(result.operation().responseType().get().fields().containsKey("age"));

        assertEquals("user.get", result.observation().attributes().get("methodName"));
        assertEquals("true", result.observation().attributes().get("hasResult"));
    }

    @Test
    void correlatesBatchResponsesById() {
        JsonRpcProtocolAnalyzer analyzer = new JsonRpcProtocolAnalyzer(new ObjectMapper());

        HttpExchange exchange = new HttpExchange(
                UUID.randomUUID(),
                URI.create("https://example.test/rpc"),
                "POST",
                Map.of("Content-Type", List.of("application/json")),
                Optional.of("[" +
                        "{\"jsonrpc\":\"2.0\",\"method\":\"a\",\"id\":1}," +
                        "{\"jsonrpc\":\"2.0\",\"method\":\"b\",\"id\":2}" +
                        "]"),
                200,
                Map.of("Content-Type", List.of("application/json")),
                Optional.of("[" +
                        "{\"jsonrpc\":\"2.0\",\"result\":{\"ok\":true},\"id\":2}," +
                        "{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-1,\"message\":\"no\"},\"id\":1}" +
                        "]"),
                Instant.parse("2026-01-01T00:00:00Z")
        );

        List<JsonRpcProtocolAnalyzer.AnalysisResult> results = analyzer.analyze(
                exchange,
                DetectionResult.detected(ProtocolKind.JSON_RPC, 1.0, "unit")
        );

        assertEquals(2, results.size());

        Map<String, String> aAttrs = results.stream()
                .filter(r -> r.operation().name().equals("a"))
                .findFirst()
                .orElseThrow()
                .observation()
                .attributes();
        assertEquals("true", aAttrs.get("hasError"));

        Map<String, String> bAttrs = results.stream()
                .filter(r -> r.operation().name().equals("b"))
                .findFirst()
                .orElseThrow()
                .observation()
                .attributes();
        assertEquals("true", bAttrs.get("hasResult"));
    }
}
