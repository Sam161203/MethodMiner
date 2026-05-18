package com.methodminer.protocol.jsonrpc;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.methodminer.protocol.DetectionResult;
import com.methodminer.protocol.HttpExchange;
import com.methodminer.protocol.ProtocolDetector;
import com.methodminer.protocol.ProtocolKind;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Detects JSON-RPC 2.0 requests.
 */
public final class JsonRpcProtocolDetector implements ProtocolDetector {
    private final ObjectMapper objectMapper;

    public JsonRpcProtocolDetector(ObjectMapper objectMapper) {
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper");
    }

    @Override
    public DetectionResult detect(HttpExchange exchange) {
        Objects.requireNonNull(exchange, "exchange");

        String body = exchange.requestBody().orElse("");
        if (body.isBlank()) {
            return DetectionResult.unknown("empty-body");
        }
        if (!looksLikeJson(body)) {
            return DetectionResult.unknown("not-json");
        }

        final JsonNode root;
        try {
            root = objectMapper.readTree(body);
        } catch (JsonProcessingException ex) {
            return DetectionResult.unknown("malformed-json");
        }

        Candidate candidate = firstCandidate(root);
        if (candidate == null) {
            return DetectionResult.unknown("missing-method");
        }

        if (candidate.jsonrpcVersion.isPresent() && !"2.0".equals(candidate.jsonrpcVersion.get())) {
            return DetectionResult.unknown("jsonrpc-version-mismatch");
        }

        double confidence = candidate.jsonrpcVersion.isPresent() ? 1.0 : 0.75;
        String reason = candidate.jsonrpcVersion.isPresent() ? "jsonrpc-2.0" : "jsonrpc-missing";

        Map<String, String> attributes = new HashMap<>();
        attributes.put("methodName", candidate.methodName);
        String namespace = JsonRpcMethodName.namespaceOf(candidate.methodName);
        if (!namespace.isBlank()) {
            attributes.put("namespace", namespace);
        }
        String simple = JsonRpcMethodName.simpleNameOf(candidate.methodName);
        if (!simple.isBlank()) {
            attributes.put("methodSimpleName", simple);
        }
        candidate.jsonrpcVersion.ifPresent(version -> attributes.put("jsonrpcVersion", version));
        attributes.put("batch", String.valueOf(candidate.batch));
        attributes.put("notification", String.valueOf(candidate.notification));
        attributes.put("paramsMode", candidate.paramsMode);
        attributes.put("idType", candidate.idType);

        return new DetectionResult(ProtocolKind.JSON_RPC, confidence, reason, Map.copyOf(attributes));
    }

    private static Candidate firstCandidate(JsonNode root) {
        if (root == null || root.isNull() || root.isMissingNode()) {
            return null;
        }

        if (root instanceof ObjectNode objectNode) {
            return parseCandidate(objectNode, false);
        }

        if (root.isArray()) {
            for (JsonNode item : root) {
                if (item instanceof ObjectNode objectNode) {
                    Candidate candidate = parseCandidate(objectNode, true);
                    if (candidate != null) {
                        return candidate;
                    }
                }
            }
        }

        return null;
    }

    private static Candidate parseCandidate(ObjectNode node, boolean batch) {
        JsonNode methodNode = node.get("method");
        if (methodNode == null || methodNode.isNull()) {
            return null;
        }

        String methodName = methodNode.isTextual() ? methodNode.asText("") : methodNode.toString();
        methodName = methodName == null ? "" : methodName.trim();
        if (methodName.isBlank()) {
            return null;
        }

        Optional<String> jsonrpcVersion = Optional.empty();
        JsonNode jsonrpcNode = node.get("jsonrpc");
        if (jsonrpcNode != null && !jsonrpcNode.isNull() && !jsonrpcNode.isMissingNode()) {
            String version = jsonrpcNode.isTextual() ? jsonrpcNode.asText("") : jsonrpcNode.toString();
            version = version == null ? "" : version.trim();
            if (!version.isBlank()) {
                jsonrpcVersion = Optional.of(version);
            }
        }

        JsonNode paramsNode = node.get("params");
        String paramsMode = detectParamsMode(paramsNode);

        JsonNode idNode = node.get("id");
        boolean notification = idNode == null || idNode.isNull() || idNode.isMissingNode();
        String idType = jsonType(idNode);

        return new Candidate(methodName, jsonrpcVersion, batch, notification, paramsMode, idType);
    }

    private static String detectParamsMode(JsonNode paramsNode) {
        if (paramsNode == null || paramsNode.isMissingNode()) {
            return "missing";
        }
        if (paramsNode.isNull()) {
            return "null";
        }
        if (paramsNode.isObject()) {
            return "named";
        }
        if (paramsNode.isArray()) {
            return "positional";
        }
        return jsonType(paramsNode);
    }

    private static boolean looksLikeJson(String bodyText) {
        for (int i = 0; i < bodyText.length(); i++) {
            char ch = bodyText.charAt(i);
            if (ch == '\uFEFF' || Character.isWhitespace(ch)) {
                continue;
            }
            return ch == '{' || ch == '[';
        }
        return false;
    }

    private static String jsonType(JsonNode node) {
        if (node == null || node.isMissingNode()) {
            return "missing";
        }
        if (node.isNull()) {
            return "null";
        }
        if (node.isTextual()) {
            return "string";
        }
        if (node.isBoolean()) {
            return "boolean";
        }
        if (node.isNumber()) {
            return node.isIntegralNumber() ? "integer" : "number";
        }
        if (node.isObject()) {
            return "object";
        }
        if (node.isArray()) {
            return "array";
        }
        return node.getNodeType().name().toLowerCase(Locale.ROOT);
    }

    private record Candidate(
            String methodName,
            Optional<String> jsonrpcVersion,
            boolean batch,
            boolean notification,
            String paramsMode,
            String idType
    ) {
    }
}
