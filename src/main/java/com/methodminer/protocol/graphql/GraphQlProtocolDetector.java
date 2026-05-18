package com.methodminer.protocol.graphql;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.methodminer.protocol.DetectionResult;
import com.methodminer.protocol.HttpExchange;
import com.methodminer.protocol.ProtocolDetector;
import com.methodminer.protocol.ProtocolKind;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Detects GraphQL requests from captured HTTP traffic.
 *
 * <p>Detection criteria:
 * <ul>
 *   <li>POST with JSON body containing a {@code "query"} string field</li>
 *   <li>GET with a {@code query} URL parameter containing GraphQL syntax</li>
 *   <li>Optional fields: {@code operationName}, {@code variables}, {@code extensions}</li>
 * </ul>
 *
 * <p>When detected, the result includes the operation name (if present) and
 * a best-effort operation type (query/mutation/subscription) parsed from the
 * document prefix.</p>
 */
public final class GraphQlProtocolDetector implements ProtocolDetector {
    private final ObjectMapper objectMapper;

    public GraphQlProtocolDetector(ObjectMapper objectMapper) {
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper");
    }

    @Override
    public DetectionResult detect(HttpExchange exchange) {
        Objects.requireNonNull(exchange, "exchange");

        String httpMethod = exchange.method() == null ? "" : exchange.method().trim().toUpperCase();

        if ("POST".equals(httpMethod)) {
            return detectFromPost(exchange);
        }
        if ("GET".equals(httpMethod)) {
            return detectFromGet(exchange);
        }

        return DetectionResult.unknown("unsupported-http-method");
    }

    // ---- POST detection ---------------------------------------------------

    private DetectionResult detectFromPost(HttpExchange exchange) {
        String body = exchange.requestBody().orElse("");
        if (body.isBlank()) {
            return DetectionResult.unknown("empty-body");
        }
        if (!looksLikeJsonObject(body)) {
            return DetectionResult.unknown("not-json-object");
        }

        JsonNode root;
        try {
            root = objectMapper.readTree(body);
        } catch (JsonProcessingException ex) {
            return DetectionResult.unknown("malformed-json");
        }

        if (!(root instanceof ObjectNode objectNode)) {
            return DetectionResult.unknown("not-json-object");
        }

        JsonNode queryNode = objectNode.get("query");
        if (queryNode == null || queryNode.isNull() || queryNode.isMissingNode()) {
            return DetectionResult.unknown("missing-query-field");
        }
        if (!queryNode.isTextual()) {
            return DetectionResult.unknown("query-not-string");
        }

        String queryText = queryNode.asText("").trim();
        if (queryText.isBlank()) {
            return DetectionResult.unknown("empty-query");
        }

        // Confidence scoring
        double confidence = 0.6; // Base: JSON body with "query" string
        String reason = "post-json-query";

        // Boost if operationName present
        JsonNode opNameNode = objectNode.get("operationName");
        if (opNameNode != null && opNameNode.isTextual() && !opNameNode.asText("").isBlank()) {
            confidence = Math.min(1.0, confidence + 0.15);
            reason = "post-json-query+operationName";
        }

        // Boost if variables present
        if (objectNode.has("variables") && !objectNode.get("variables").isNull()) {
            confidence = Math.min(1.0, confidence + 0.1);
        }

        // Boost if query text looks like GraphQL syntax
        if (looksLikeGraphQlSyntax(queryText)) {
            confidence = Math.min(1.0, confidence + 0.15);
        }

        // Boost if path contains /graphql
        if (pathHint(exchange.uri())) {
            confidence = Math.min(1.0, confidence + 0.1);
        }

        Map<String, String> attributes = buildAttributes(queryText, objectNode);
        return new DetectionResult(ProtocolKind.GRAPHQL, confidence, reason, Map.copyOf(attributes));
    }

    // ---- GET detection ----------------------------------------------------

    private DetectionResult detectFromGet(HttpExchange exchange) {
        String rawQuery = exchange.uri().getRawQuery();
        if (rawQuery == null || rawQuery.isBlank()) {
            return DetectionResult.unknown("no-query-params");
        }

        Map<String, String> params = parseQueryParams(rawQuery);
        String queryText = params.getOrDefault("query", "").trim();
        if (queryText.isBlank()) {
            return DetectionResult.unknown("missing-query-param");
        }

        if (!looksLikeGraphQlSyntax(queryText)) {
            return DetectionResult.unknown("query-not-graphql-syntax");
        }

        double confidence = 0.7;
        String reason = "get-query-param";

        if (pathHint(exchange.uri())) {
            confidence = Math.min(1.0, confidence + 0.1);
        }
        if (params.containsKey("operationName")) {
            confidence = Math.min(1.0, confidence + 0.1);
        }

        Map<String, String> attributes = new HashMap<>();
        attributes.put("queryDocument", queryText);

        String operationType = detectOperationType(queryText);
        if (!operationType.isBlank()) {
            attributes.put("operationType", operationType);
        }

        String operationName = params.getOrDefault("operationName", "").trim();
        if (operationName.isBlank()) {
            operationName = extractOperationName(queryText);
        }
        if (!operationName.isBlank()) {
            attributes.put("operationName", operationName);
        }

        return new DetectionResult(ProtocolKind.GRAPHQL, confidence, reason, Map.copyOf(attributes));
    }

    // ---- Attribute building -----------------------------------------------

    private static Map<String, String> buildAttributes(String queryText, ObjectNode root) {
        Map<String, String> attributes = new HashMap<>();
        attributes.put("queryDocument", queryText);

        String operationType = detectOperationType(queryText);
        if (!operationType.isBlank()) {
            attributes.put("operationType", operationType);
        }

        JsonNode opNameNode = root.get("operationName");
        String operationName = "";
        if (opNameNode != null && opNameNode.isTextual()) {
            operationName = opNameNode.asText("").trim();
        }
        if (operationName.isBlank()) {
            operationName = extractOperationName(queryText);
        }
        if (!operationName.isBlank()) {
            attributes.put("operationName", operationName);
        }

        if (root.has("variables")) {
            attributes.put("hasVariables", "true");
        }
        if (root.has("extensions")) {
            attributes.put("hasExtensions", "true");
        }

        return attributes;
    }

    // ---- GraphQL heuristics -----------------------------------------------

    /**
     * Checks if the query text begins with a GraphQL keyword or a selection set.
     */
    static boolean looksLikeGraphQlSyntax(String queryText) {
        if (queryText == null || queryText.isBlank()) {
            return false;
        }
        String stripped = stripLeadingWhitespaceAndComments(queryText);
        if (stripped.isBlank()) {
            return false;
        }

        // Selection set shorthand: { user { ... } }
        if (stripped.charAt(0) == '{') {
            return true;
        }

        // Keyword: query, mutation, subscription, fragment
        String lower = stripped.toLowerCase();
        return lower.startsWith("query ")
                || lower.startsWith("query{")
                || lower.startsWith("query(")
                || lower.startsWith("mutation ")
                || lower.startsWith("mutation{")
                || lower.startsWith("mutation(")
                || lower.startsWith("subscription ")
                || lower.startsWith("subscription{")
                || lower.startsWith("subscription(")
                || lower.startsWith("fragment ");
    }

    /**
     * Extracts the operation type (query/mutation/subscription) from the document prefix.
     * Returns empty string if not determinable.
     */
    static String detectOperationType(String queryText) {
        if (queryText == null || queryText.isBlank()) {
            return "";
        }
        String stripped = stripLeadingWhitespaceAndComments(queryText).toLowerCase();

        if (stripped.startsWith("mutation")) {
            return "mutation";
        }
        if (stripped.startsWith("subscription")) {
            return "subscription";
        }
        if (stripped.startsWith("query")) {
            return "query";
        }
        // Selection set shorthand implies query
        if (stripped.startsWith("{")) {
            return "query";
        }
        return "";
    }

    /**
     * Extracts the operation name from a GraphQL document prefix.
     * Example: {@code query GetUser($id: ID!) { ... }} → "GetUser"
     */
    static String extractOperationName(String queryText) {
        if (queryText == null || queryText.isBlank()) {
            return "";
        }

        String stripped = stripLeadingWhitespaceAndComments(queryText);

        // Must start with a keyword to have a named operation
        String[] keywords = {"query", "mutation", "subscription"};
        for (String keyword : keywords) {
            if (stripped.length() > keyword.length()
                    && stripped.substring(0, keyword.length()).equalsIgnoreCase(keyword)) {
                String remainder = stripped.substring(keyword.length()).trim();
                if (remainder.isEmpty() || remainder.charAt(0) == '{') {
                    return ""; // Anonymous
                }
                // Extract name: first identifier before ( or { or space
                StringBuilder name = new StringBuilder();
                for (int i = 0; i < remainder.length(); i++) {
                    char ch = remainder.charAt(i);
                    if (Character.isLetterOrDigit(ch) || ch == '_') {
                        name.append(ch);
                    } else {
                        break;
                    }
                }
                return name.toString();
            }
        }

        return "";
    }

    // ---- Utility -----------------------------------------------------------

    private static boolean looksLikeJsonObject(String text) {
        if (text == null) {
            return false;
        }
        for (int i = 0; i < text.length(); i++) {
            char ch = text.charAt(i);
            if (ch == '\uFEFF' || Character.isWhitespace(ch)) {
                continue;
            }
            return ch == '{';
        }
        return false;
    }

    private static boolean pathHint(URI uri) {
        if (uri == null) {
            return false;
        }
        String path = uri.getPath();
        if (path == null || path.isBlank()) {
            return false;
        }
        String lower = path.toLowerCase();
        return lower.contains("/graphql") || lower.contains("/gql");
    }

    /**
     * Strip leading whitespace and single/multi-line comments from a GraphQL document.
     */
    private static String stripLeadingWhitespaceAndComments(String text) {
        int i = 0;
        while (i < text.length()) {
            char ch = text.charAt(i);
            if (Character.isWhitespace(ch) || ch == '\uFEFF') {
                i++;
                continue;
            }
            // Single-line comment
            if (ch == '#') {
                int nl = text.indexOf('\n', i);
                if (nl < 0) {
                    return "";
                }
                i = nl + 1;
                continue;
            }
            break;
        }
        return i < text.length() ? text.substring(i) : "";
    }

    private static Map<String, String> parseQueryParams(String rawQuery) {
        Map<String, String> params = new HashMap<>();
        if (rawQuery == null || rawQuery.isBlank()) {
            return params;
        }
        for (String pair : rawQuery.split("&")) {
            int eq = pair.indexOf('=');
            if (eq <= 0) {
                continue;
            }
            String key = urlDecode(pair.substring(0, eq));
            String value = urlDecode(pair.substring(eq + 1));
            params.putIfAbsent(key, value);
        }
        return params;
    }

    private static String urlDecode(String value) {
        try {
            return URLDecoder.decode(value, StandardCharsets.UTF_8);
        } catch (Exception ex) {
            return value;
        }
    }
}
