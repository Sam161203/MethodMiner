package com.methodminer.protocol.graphql;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.methodminer.core.model.OperationKind;
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

import static org.junit.jupiter.api.Assertions.*;

class GraphQlProtocolAnalyzerTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private final GraphQlProtocolAnalyzer analyzer = new GraphQlProtocolAnalyzer(mapper);
    private final GraphQlProtocolDetector detector = new GraphQlProtocolDetector(mapper);

    @Test
    void analyzesQueryWithFieldsAndVariables() {
        HttpExchange exchange = graphqlExchange(
                "{\"query\":\"query GetUser($id: ID!) { user(id: $id) { name email } }\","
                        + "\"operationName\":\"GetUser\","
                        + "\"variables\":{\"id\":\"abc-123\"}}"
        );
        DetectionResult detection = detector.detect(exchange);
        assertEquals(ProtocolKind.GRAPHQL, detection.kind());

        var results = analyzer.analyze(exchange, detection);
        assertEquals(1, results.size());

        var result = results.get(0);
        assertEquals(ProtocolKind.GRAPHQL, result.operation().protocolKind());
        assertEquals(OperationKind.QUERY, result.operation().kind());
        assertTrue(result.operation().name().contains("GetUser"));

        // Should have variable parameter
        assertTrue(result.operation().parameters().stream()
                .anyMatch(p -> p.name().equals("$id")));

        // Should have response type with user fields
        assertTrue(result.operation().responseType().isPresent());
        assertTrue(result.operation().responseType().get().fields().containsKey("user"));
    }

    @Test
    void analyzesMutationWithVariables() {
        HttpExchange exchange = graphqlExchange(
                "{\"query\":\"mutation UpdateUser($input: UpdateUserInput!) { updateUser(input: $input) { success } }\","
                        + "\"operationName\":\"UpdateUser\","
                        + "\"variables\":{\"input\":{\"name\":\"Alice\",\"email\":\"alice@test.com\"}}}"
        );
        DetectionResult detection = detector.detect(exchange);
        var results = analyzer.analyze(exchange, detection);

        assertEquals(1, results.size());
        assertEquals(OperationKind.MUTATION, results.get(0).operation().kind());
        assertTrue(results.get(0).operation().name().contains("UpdateUser"));

        // Variable $input should be detected as object type
        var inputParam = results.get(0).operation().parameters().stream()
                .filter(p -> p.name().equals("$input")).findFirst();
        assertTrue(inputParam.isPresent());
    }

    @Test
    void parsesTopLevelFieldsFromDocument() {
        var fields = GraphQlProtocolAnalyzer.parseTopLevelFields(
                "query { user { name } posts { title } }"
        );
        assertEquals(2, fields.size());
        assertEquals("user", fields.get(0).name());
        assertEquals("posts", fields.get(1).name());
        assertTrue(fields.get(0).hasSubfields());
        assertTrue(fields.get(1).hasSubfields());
    }

    @Test
    void parsesFieldArguments() {
        var fields = GraphQlProtocolAnalyzer.parseTopLevelFields(
                "query { user(id: 123) { name } }"
        );
        assertEquals(1, fields.size());
        assertEquals("user", fields.get(0).name());
        assertTrue(fields.get(0).arguments().containsKey("id"));
        assertEquals("123", fields.get(0).arguments().get("id"));
    }

    @Test
    void parsesAliasedFields() {
        var fields = GraphQlProtocolAnalyzer.parseTopLevelFields(
                "query { myUser: user { name } }"
        );
        assertEquals(1, fields.size());
        assertEquals("user", fields.get(0).name());
    }

    @Test
    void handlesShorthandQuery() {
        var fields = GraphQlProtocolAnalyzer.parseTopLevelFields("{ viewer { login } }");
        assertEquals(1, fields.size());
        assertEquals("viewer", fields.get(0).name());
    }

    @Test
    void handlesEmptyAndMalformedDocuments() {
        assertTrue(GraphQlProtocolAnalyzer.parseTopLevelFields("").isEmpty());
        assertTrue(GraphQlProtocolAnalyzer.parseTopLevelFields(null).isEmpty());
        assertTrue(GraphQlProtocolAnalyzer.parseTopLevelFields("just text no braces").isEmpty());
    }

    @Test
    void rejectsNonGraphQlDetection() {
        HttpExchange exchange = graphqlExchange("{\"query\":\"{ user { id } }\"}");
        DetectionResult jsonRpcDetection = DetectionResult.detected(ProtocolKind.JSON_RPC, 1.0, "wrong");
        var results = analyzer.analyze(exchange, jsonRpcDetection);
        assertTrue(results.isEmpty());
    }

    @Test
    void observationContainsExpectedAttributes() {
        HttpExchange exchange = graphqlExchange(
                "{\"query\":\"query GetUser { user { id } }\",\"operationName\":\"GetUser\"}"
        );
        DetectionResult detection = detector.detect(exchange);
        var results = analyzer.analyze(exchange, detection);

        assertEquals(1, results.size());
        var attrs = results.get(0).observation().attributes();
        assertEquals("query", attrs.get("operationType"));
        assertEquals("GetUser", attrs.get("operationName"));
        assertEquals("200", attrs.get("responseStatusCode"));
    }

    private static HttpExchange graphqlExchange(String body) {
        return new HttpExchange(
                UUID.randomUUID(),
                URI.create("https://api.example.com/graphql"),
                "POST",
                Map.of("Content-Type", List.of("application/json")),
                Optional.of(body),
                200,
                Map.of("Content-Type", List.of("application/json")),
                Optional.of("{\"data\":{\"user\":{\"id\":\"1\"}}}"),
                Instant.parse("2026-01-01T00:00:00Z")
        );
    }
}
