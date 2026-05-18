package com.methodminer.protocol.graphql;

import com.methodminer.protocol.DetectionResult;
import com.methodminer.protocol.HttpExchange;
import com.methodminer.protocol.ProtocolKind;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class GraphQlProtocolDetectorTest {

    private final GraphQlProtocolDetector detector = new GraphQlProtocolDetector(new ObjectMapper());

    @Test
    void detectsPostGraphQlQuery() {
        HttpExchange exchange = postExchange(
                "https://api.example.com/graphql",
                "{\"query\":\"query GetUser { user { id name } }\",\"operationName\":\"GetUser\"}"
        );
        DetectionResult result = detector.detect(exchange);
        assertEquals(ProtocolKind.GRAPHQL, result.kind());
        assertTrue(result.confidence() >= 0.7);
        assertEquals("GetUser", result.attributes().get("operationName"));
        assertEquals("query", result.attributes().get("operationType"));
    }

    @Test
    void detectsPostGraphQlMutation() {
        HttpExchange exchange = postExchange(
                "https://api.example.com/graphql",
                "{\"query\":\"mutation UpdateUser($id: ID!) { updateUser(id: $id) { success } }\",\"variables\":{\"id\":\"123\"}}"
        );
        DetectionResult result = detector.detect(exchange);
        assertEquals(ProtocolKind.GRAPHQL, result.kind());
        assertEquals("mutation", result.attributes().get("operationType"));
        assertEquals("UpdateUser", result.attributes().get("operationName"));
        assertEquals("true", result.attributes().get("hasVariables"));
    }

    @Test
    void detectsShorthandQuery() {
        HttpExchange exchange = postExchange(
                "https://api.example.com/graphql",
                "{\"query\":\"{ viewer { login } }\"}"
        );
        DetectionResult result = detector.detect(exchange);
        assertEquals(ProtocolKind.GRAPHQL, result.kind());
        assertEquals("query", result.attributes().get("operationType"));
    }

    @Test
    void rejectsBodyWithoutQueryField() {
        HttpExchange exchange = postExchange(
                "https://api.example.com/graphql",
                "{\"data\":\"not a graphql request\"}"
        );
        DetectionResult result = detector.detect(exchange);
        assertEquals(ProtocolKind.UNKNOWN, result.kind());
    }

    @Test
    void rejectsEmptyBody() {
        HttpExchange exchange = postExchange("https://api.example.com/graphql", "");
        DetectionResult result = detector.detect(exchange);
        assertEquals(ProtocolKind.UNKNOWN, result.kind());
    }

    @Test
    void detectsGetGraphQlRequest() {
        HttpExchange exchange = new HttpExchange(
                UUID.randomUUID(),
                URI.create("https://api.example.com/graphql?query=%7B%20viewer%20%7B%20login%20%7D%20%7D&operationName=Viewer"),
                "GET",
                Map.of(), Optional.empty(), 200, Map.of(), Optional.empty(),
                Instant.parse("2026-01-01T00:00:00Z")
        );
        DetectionResult result = detector.detect(exchange);
        assertEquals(ProtocolKind.GRAPHQL, result.kind());
    }

    @Test
    void detectsSubscription() {
        HttpExchange exchange = postExchange(
                "https://api.example.com/graphql",
                "{\"query\":\"subscription OnMessage { messageAdded { text } }\"}"
        );
        DetectionResult result = detector.detect(exchange);
        assertEquals(ProtocolKind.GRAPHQL, result.kind());
        assertEquals("subscription", result.attributes().get("operationType"));
        assertEquals("OnMessage", result.attributes().get("operationName"));
    }

    @Test
    void extractsOperationNameFromDocumentWhenNotInBody() {
        HttpExchange exchange = postExchange(
                "https://api.example.com/graphql",
                "{\"query\":\"query FetchPosts { posts { id title } }\"}"
        );
        DetectionResult result = detector.detect(exchange);
        assertEquals("FetchPosts", result.attributes().get("operationName"));
    }

    @Test
    void looksLikeGraphQlSyntaxRecognizesKeywords() {
        assertTrue(GraphQlProtocolDetector.looksLikeGraphQlSyntax("query { user { id } }"));
        assertTrue(GraphQlProtocolDetector.looksLikeGraphQlSyntax("mutation { updateUser { success } }"));
        assertTrue(GraphQlProtocolDetector.looksLikeGraphQlSyntax("{ viewer { login } }"));
        assertFalse(GraphQlProtocolDetector.looksLikeGraphQlSyntax("SELECT * FROM users"));
        assertFalse(GraphQlProtocolDetector.looksLikeGraphQlSyntax(""));
        assertFalse(GraphQlProtocolDetector.looksLikeGraphQlSyntax(null));
    }

    @Test
    void handlesCommentsBeforeQuery() {
        assertTrue(GraphQlProtocolDetector.looksLikeGraphQlSyntax("# comment\nquery { user { id } }"));
        assertEquals("query", GraphQlProtocolDetector.detectOperationType("# comment\nquery { user { id } }"));
    }

    private static HttpExchange postExchange(String url, String body) {
        return new HttpExchange(
                UUID.randomUUID(),
                URI.create(url),
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
