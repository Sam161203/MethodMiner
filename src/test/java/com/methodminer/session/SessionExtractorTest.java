package com.methodminer.session;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.methodminer.protocol.HttpExchange;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link SessionExtractor}.
 */
class SessionExtractorTest {

    private SessionExtractor extractor;

    @BeforeEach
    void setUp() {
        extractor = new SessionExtractor(new ObjectMapper());
    }

    @Test
    void bearerTokenExtraction() {
        HttpExchange exchange = exchange(
                Map.of("Authorization", List.of("Bearer eyJhbGciOiJIUzI1NiJ9.test")),
                Optional.empty()
        );

        SessionFingerprint fp = extractor.extract(exchange);
        assertFalse(fp.isEmpty());
        assertEquals("Bearer", fp.authMechanism());
        assertFalse(fp.tokenHash().isBlank());
        assertEquals(16, fp.tokenHash().length(), "Token hash should be 16 hex chars");
        assertTrue(fp.authHeaderNames().contains("Authorization"));
    }

    @Test
    void basicAuthExtractsUsername() {
        String encoded = Base64.getEncoder().encodeToString("admin@example.com:secret123".getBytes());
        HttpExchange exchange = exchange(
                Map.of("Authorization", List.of("Basic " + encoded)),
                Optional.empty()
        );

        SessionFingerprint fp = extractor.extract(exchange);
        assertFalse(fp.isEmpty());
        assertEquals("Basic", fp.authMechanism());
        assertEquals("admin@example.com", fp.username());
        assertFalse(fp.tokenHash().isBlank());
    }

    @Test
    void cookieExtractionExtractsNamesNotValues() {
        HttpExchange exchange = exchange(
                Map.of("Cookie", List.of("sessionId=abc123; token=xyz789; pref=dark")),
                Optional.empty()
        );

        SessionFingerprint fp = extractor.extract(exchange);
        assertFalse(fp.isEmpty());
        assertEquals("Cookie", fp.authMechanism());
        assertTrue(fp.cookieNames().contains("sessionId"));
        assertTrue(fp.cookieNames().contains("token"));
        assertTrue(fp.cookieNames().contains("pref"));
        assertFalse(fp.tokenHash().isBlank());
    }

    @Test
    void apiKeyHeaderExtraction() {
        HttpExchange exchange = exchange(
                Map.of("X-API-Key", List.of("sk-live-1234567890abcdef")),
                Optional.empty()
        );

        SessionFingerprint fp = extractor.extract(exchange);
        assertFalse(fp.isEmpty());
        assertEquals("API-Key", fp.authMechanism());
        assertTrue(fp.authHeaderNames().contains("X-API-Key"));
        assertFalse(fp.tokenHash().isBlank());
    }

    @Test
    void jsonRpcCredentialsExtraction() {
        String body = """
            {
                "jsonrpc": "2.0",
                "method": "Get",
                "params": {
                    "typeName": "Device",
                    "credentials": {
                        "database": "black_sky_7569",
                        "userName": "user@example.com",
                        "sessionId": "abc-def-123-session"
                    }
                }
            }
            """;

        HttpExchange exchange = exchange(Map.of(), Optional.of(body));

        SessionFingerprint fp = extractor.extract(exchange);
        assertFalse(fp.isEmpty());
        assertEquals("JSON-RPC-credentials", fp.authMechanism());
        assertEquals("user@example.com", fp.username());
        assertEquals("black_sky_7569", fp.database());
        assertFalse(fp.tokenHash().isBlank());
    }

    @Test
    void graphQlVariableCredentialExtraction() {
        String body = """
            {
                "query": "mutation Login($token: String!) { login(token: $token) { success } }",
                "variables": {
                    "token": "my-secret-auth-token"
                }
            }
            """;

        HttpExchange exchange = exchange(Map.of(), Optional.of(body));

        SessionFingerprint fp = extractor.extract(exchange);
        assertFalse(fp.isEmpty());
        assertEquals("GraphQL-variable", fp.authMechanism());
        assertFalse(fp.tokenHash().isBlank());
    }

    @Test
    void noAuthReturnsEmptyFingerprint() {
        HttpExchange exchange = exchange(
                Map.of("Content-Type", List.of("application/json")),
                Optional.of("{\"data\": \"test\"}")
        );

        SessionFingerprint fp = extractor.extract(exchange);
        assertTrue(fp.isEmpty());
    }

    @Test
    void hashTokenProducesConsistentHashes() {
        String hash1 = SessionExtractor.hashToken("same-value");
        String hash2 = SessionExtractor.hashToken("same-value");
        assertEquals(hash1, hash2);
        assertEquals(16, hash1.length());

        String different = SessionExtractor.hashToken("different-value");
        assertNotEquals(hash1, different);
    }
    
    @Test
    void nullExchangeReturnsEmpty() {
        SessionFingerprint fp = extractor.extract(null);
        assertTrue(fp.isEmpty());
    }

    // ---- Helpers ----------------------------------------------------------

    private static HttpExchange exchange(Map<String, List<String>> headers, Optional<String> body) {
        return new HttpExchange(
                UUID.randomUUID(),
                URI.create("https://api.example.com/rpc"),
                "POST",
                headers,
                body,
                200,
                Map.of(),
                Optional.empty(),
                Instant.now()
        );
    }
}
