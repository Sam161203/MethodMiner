package com.methodminer.session;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.methodminer.protocol.HttpExchange;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

/**
 * Stateless engine that inspects an {@link HttpExchange} and produces a {@link SessionFingerprint}.
 *
 * <p>Detects authentication material from:
 * <ul>
 *   <li>Authorization headers (Bearer, Basic, API keys)</li>
 *   <li>Cookie headers (extracts names, hashes values)</li>
 *   <li>Custom auth headers (X-API-Key, X-Auth-Token, X-Session-Id, etc.)</li>
 *   <li>JSON-RPC credentials blocks (params.credentials.{sessionId, database, userName})</li>
 *   <li>GraphQL variables containing credential-like keys</li>
 * </ul>
 *
 * <p><strong>Security:</strong> Never stores raw secrets. All token values are SHA-256 hashed
 * and truncated to the first 16 hex characters.
 */
public final class SessionExtractor {

    /** Header names (lowercase) that indicate auth material. */
    private static final Set<String> AUTH_HEADER_NAMES = Set.of(
            "x-api-key", "x-auth-token", "x-session-id", "x-access-token",
            "x-csrf-token", "x-xsrf-token", "x-request-id"
    );

    /** Variable keys (lowercase) in GraphQL that look credential-like. */
    private static final Set<String> CREDENTIAL_VARIABLE_KEYS = Set.of(
            "token", "apikey", "api_key", "authtoken", "auth_token",
            "accesstoken", "access_token", "sessionid", "session_id",
            "password", "secret", "credential", "credentials"
    );

    private final ObjectMapper objectMapper;

    public SessionExtractor(ObjectMapper objectMapper) {
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper");
    }

    /**
     * Extract a session fingerprint from the given HTTP exchange.
     *
     * @return a fingerprint summarizing detected auth material, or {@link SessionFingerprint#EMPTY}
     */
    public SessionFingerprint extract(HttpExchange exchange) {
        if (exchange == null) return SessionFingerprint.EMPTY;

        String host = exchange.uri() != null && exchange.uri().getHost() != null
                ? exchange.uri().getHost().toLowerCase(Locale.ROOT) : "";

        String authMechanism = "";
        String tokenHash = "";
        String username = "";
        String database = "";
        Set<String> cookieNames = new LinkedHashSet<>();
        Set<String> authHeaderNames = new LinkedHashSet<>();
        Map<String, String> metadata = new LinkedHashMap<>();

        // 1. Authorization header
        AuthResult authResult = extractAuthorization(exchange.requestHeaders());
        if (authResult != null) {
            authMechanism = authResult.mechanism;
            tokenHash = authResult.tokenHash;
            if (!authResult.username.isBlank()) username = authResult.username;
            authHeaderNames.add("Authorization");
        }

        // 2. Cookie header
        Set<String> cookies = extractCookieNames(exchange.requestHeaders());
        cookieNames.addAll(cookies);
        if (!cookies.isEmpty() && tokenHash.isBlank()) {
            // Use combined cookie hash as fingerprint if no auth header
            String combinedCookieValue = extractCookieRawForHashing(exchange.requestHeaders());
            if (!combinedCookieValue.isBlank()) {
                tokenHash = hashToken(combinedCookieValue);
                if (authMechanism.isBlank()) authMechanism = "Cookie";
            }
        }

        // 3. Custom auth headers
        for (var entry : exchange.requestHeaders().entrySet()) {
            String headerLower = entry.getKey().toLowerCase(Locale.ROOT);
            if (AUTH_HEADER_NAMES.contains(headerLower)) {
                authHeaderNames.add(entry.getKey());
                if (tokenHash.isBlank() && entry.getValue() != null && !entry.getValue().isEmpty()) {
                    String val = entry.getValue().get(0);
                    if (val != null && !val.isBlank()) {
                        tokenHash = hashToken(val.trim());
                        if (authMechanism.isBlank()) authMechanism = "API-Key";
                    }
                }
            }
        }

        // 4. JSON body credential extraction (JSON-RPC + GraphQL)
        String body = exchange.requestBody().orElse("");
        if (!body.isBlank()) {
            BodyCredentials bodyCreds = extractBodyCredentials(body);
            if (bodyCreds != null) {
                if (!bodyCreds.username.isBlank() && username.isBlank()) username = bodyCreds.username;
                if (!bodyCreds.database.isBlank() && database.isBlank()) database = bodyCreds.database;
                if (!bodyCreds.tokenHash.isBlank() && tokenHash.isBlank()) tokenHash = bodyCreds.tokenHash;
                if (!bodyCreds.mechanism.isBlank()) {
                    if (authMechanism.isBlank()) authMechanism = bodyCreds.mechanism;
                }
                metadata.putAll(bodyCreds.metadata);
            }
        }

        // If nothing detected, return empty
        if (tokenHash.isBlank() && cookieNames.isEmpty() && authHeaderNames.isEmpty()
                && username.isBlank() && database.isBlank()) {
            return SessionFingerprint.EMPTY;
        }

        return new SessionFingerprint(host, authMechanism, tokenHash, username, database,
                Set.copyOf(cookieNames), Set.copyOf(authHeaderNames), Map.copyOf(metadata));
    }

    // ---- Authorization header parsing -------------------------------------

    private static AuthResult extractAuthorization(Map<String, List<String>> headers) {
        for (var entry : headers.entrySet()) {
            if (!"authorization".equalsIgnoreCase(entry.getKey())) continue;
            if (entry.getValue() == null || entry.getValue().isEmpty()) continue;
            String value = entry.getValue().get(0);
            if (value == null || value.isBlank()) continue;

            value = value.trim();

            // Bearer token
            if (value.regionMatches(true, 0, "Bearer ", 0, 7)) {
                String token = value.substring(7).trim();
                return new AuthResult("Bearer", hashToken(token), "");
            }

            // Basic auth — decode to extract username only
            if (value.regionMatches(true, 0, "Basic ", 0, 6)) {
                String encoded = value.substring(6).trim();
                String decoded = decodeBasic(encoded);
                String user = "";
                if (decoded != null) {
                    int colon = decoded.indexOf(':');
                    user = colon >= 0 ? decoded.substring(0, colon) : decoded;
                }
                return new AuthResult("Basic", hashToken(encoded), user);
            }

            // Generic token
            return new AuthResult("Token", hashToken(value), "");
        }
        return null;
    }

    private static String decodeBasic(String encoded) {
        try {
            return new String(Base64.getDecoder().decode(encoded), StandardCharsets.UTF_8);
        } catch (Exception ignored) {
            return null;
        }
    }

    // ---- Cookie parsing ---------------------------------------------------

    private static Set<String> extractCookieNames(Map<String, List<String>> headers) {
        Set<String> names = new LinkedHashSet<>();
        for (var entry : headers.entrySet()) {
            if (!"cookie".equalsIgnoreCase(entry.getKey())) continue;
            if (entry.getValue() == null) continue;
            for (String cookieHeader : entry.getValue()) {
                if (cookieHeader == null || cookieHeader.isBlank()) continue;
                for (String pair : cookieHeader.split(";")) {
                    String trimmed = pair.trim();
                    int eq = trimmed.indexOf('=');
                    String name = eq >= 0 ? trimmed.substring(0, eq).trim() : trimmed;
                    if (!name.isBlank()) names.add(name);
                }
            }
        }
        return names;
    }

    private static String extractCookieRawForHashing(Map<String, List<String>> headers) {
        for (var entry : headers.entrySet()) {
            if (!"cookie".equalsIgnoreCase(entry.getKey())) continue;
            if (entry.getValue() == null || entry.getValue().isEmpty()) continue;
            return entry.getValue().get(0);
        }
        return "";
    }

    // ---- Body credential extraction ---------------------------------------

    private BodyCredentials extractBodyCredentials(String body) {
        try {
            JsonNode root = objectMapper.readTree(body);
            if (root == null || root.isNull()) return null;

            // JSON-RPC: single call or batch
            BodyCredentials jsonRpc = extractJsonRpcCredentials(root);
            if (jsonRpc != null) return jsonRpc;

            // GraphQL variables
            BodyCredentials graphql = extractGraphQlVariableCredentials(root);
            if (graphql != null) return graphql;

            return null;
        } catch (Exception ignored) {
            return null;
        }
    }

    private static BodyCredentials extractJsonRpcCredentials(JsonNode root) {
        // Try single call
        BodyCredentials result = extractFromJsonRpcCall(root);
        if (result != null) return result;

        // Try batch
        if (root.isArray()) {
            for (JsonNode item : root) {
                result = extractFromJsonRpcCall(item);
                if (result != null) return result;
            }
        }
        return null;
    }

    private static BodyCredentials extractFromJsonRpcCall(JsonNode call) {
        if (call == null || !call.isObject()) return null;
        JsonNode params = call.get("params");
        if (params == null || !params.isObject()) return null;
        JsonNode creds = params.get("credentials");
        if (creds == null || !creds.isObject()) return null;

        String sessionId = safeText(creds, "sessionId");
        if (sessionId.isBlank()) return null;

        String database = safeText(creds, "database");
        String userName = safeText(creds, "userName");

        Map<String, String> meta = new LinkedHashMap<>();
        meta.put("credentialSource", "JSON-RPC");

        return new BodyCredentials("JSON-RPC-credentials", hashToken(sessionId),
                userName, database, meta);
    }

    private static BodyCredentials extractGraphQlVariableCredentials(JsonNode root) {
        if (!root.isObject()) return null;
        JsonNode variables = root.get("variables");
        if (variables == null || !variables.isObject()) return null;

        // Only process if there's also a "query" field (confirms GraphQL)
        if (!root.has("query")) return null;

        String tokenHash = "";
        Map<String, String> meta = new LinkedHashMap<>();

        var it = variables.fields();
        while (it.hasNext()) {
            var entry = it.next();
            String keyLower = entry.getKey().toLowerCase(Locale.ROOT);
            if (CREDENTIAL_VARIABLE_KEYS.contains(keyLower)) {
                JsonNode val = entry.getValue();
                if (val != null && val.isTextual() && !val.asText("").isBlank()) {
                    if (tokenHash.isBlank()) {
                        tokenHash = hashToken(val.asText(""));
                    }
                    meta.put("credentialVariable", entry.getKey());
                }
            }
        }

        if (tokenHash.isBlank() && meta.isEmpty()) return null;

        return new BodyCredentials("GraphQL-variable", tokenHash, "", "", meta);
    }

    // ---- Hashing ----------------------------------------------------------

    /** SHA-256 hash truncated to first 16 hex characters. Never stores raw secrets. */
    static String hashToken(String raw) {
        if (raw == null || raw.isBlank()) return "";
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(raw.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < Math.min(8, hash.length); i++) {
                sb.append(String.format("%02x", hash[i]));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is mandated by the JVM spec — this should never happen
            return "";
        }
    }

    // ---- Helpers ----------------------------------------------------------

    private static String safeText(JsonNode parent, String field) {
        JsonNode node = parent.get(field);
        if (node == null || node.isNull()) return "";
        return node.asText("").trim();
    }

    private record AuthResult(String mechanism, String tokenHash, String username) {}
    private record BodyCredentials(String mechanism, String tokenHash, String username,
                                   String database, Map<String, String> metadata) {}
}
