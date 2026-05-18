package com.methodminer.protocol.graphql;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.methodminer.core.model.*;
import com.methodminer.protocol.*;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

/**
 * Passive GraphQL analyzer that creates protocol-agnostic surface model objects
 * from captured GraphQL HTTP exchanges.
 *
 * <p>Performs lightweight, conservative parsing of GraphQL documents without
 * requiring an external GraphQL library. Extracts operation type, name,
 * top-level fields, arguments, and variable types from runtime values.</p>
 */
public final class GraphQlProtocolAnalyzer {
    private static final int MAX_TYPE_DEPTH = 6;
    private static final int MAX_FIELDS = 64;

    private final ObjectMapper objectMapper;

    public GraphQlProtocolAnalyzer(ObjectMapper objectMapper) {
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper");
    }

    /**
     * Analyze a detected GraphQL exchange and produce surface model artifacts.
     */
    public List<AnalysisResult> analyze(HttpExchange exchange, DetectionResult detection) {
        Objects.requireNonNull(exchange, "exchange");
        Objects.requireNonNull(detection, "detection");
        if (detection.kind() != ProtocolKind.GRAPHQL) {
            return List.of();
        }

        String queryDocument = detection.attributes().getOrDefault("queryDocument", "");
        if (queryDocument.isBlank()) {
            return List.of();
        }

        String detectedOpName = detection.attributes().getOrDefault("operationName", "");
        String detectedOpType = detection.attributes().getOrDefault("operationType", "query");

        // Parse variables from request body
        JsonNode variablesNode = parseVariables(exchange);

        // Parse top-level fields from document
        List<FieldInfo> topFields = parseTopLevelFields(queryDocument);

        // Build operation name
        String operationName = detectedOpName.isBlank()
                ? buildAnonymousName(detectedOpType, topFields)
                : detectedOpName;

        // Build host/path/service IDs
        String host = normalizeHost(exchange.uri().getHost());
        String scheme = exchange.uri().getScheme() == null ? "" : exchange.uri().getScheme().toLowerCase(Locale.ROOT);
        int port = effectivePort(scheme, exchange.uri().getPort());
        String path = normalizePath(exchange.uri().getPath());
        String httpMethod = exchange.method() == null ? "" : exchange.method().trim().toUpperCase(Locale.ROOT);

        String serviceKey = scheme + "://" + host + ":" + port;
        UUID serviceId = stableId("service", serviceKey);
        UUID endpointId = stableId("endpoint", serviceKey + "|" + httpMethod + "|" + path + "|" + ProtocolKind.GRAPHQL);
        UUID operationId = stableId("operation", endpointId + "|" + detectedOpType + "|" + operationName);

        OperationKind operationKind = mapOperationKind(detectedOpType);

        // Build parameters from variables
        List<Parameter> parameters = buildVariableParameters(operationId, variablesNode);

        // Build parameters from top-level field arguments
        for (FieldInfo field : topFields) {
            for (var arg : field.arguments.entrySet()) {
                UUID paramId = stableId("param", operationId + "|arg|" + field.name + "." + arg.getKey());
                DataType argType = inferScalarType(paramId, arg.getValue());
                parameters.add(new Parameter(paramId, arg.getKey(),
                        "$." + field.name + "." + arg.getKey(),
                        ParameterSource.GRAPHQL_VARIABLE, false, argType, false, List.of()));
            }
        }

        // Build response type from top-level fields (selection set)
        DataType responseType = buildSelectionSetType(operationId, operationName, topFields);

        String displayName = detectedOpType + " " + operationName;

        Operation operation = new Operation(operationId, ProtocolKind.GRAPHQL, displayName,
                operationKind, List.copyOf(parameters), Optional.empty(),
                Optional.ofNullable(responseType));

        Set<String> contentTypes = extractContentTypes(exchange.requestHeaders());
        Endpoint endpoint = new Endpoint(endpointId, ProtocolKind.GRAPHQL, httpMethod, path,
                contentTypes, List.of(operation));

        Service service = new Service(serviceId, host.isBlank() ? "(unknown host)" : host,
                host, "", List.of(endpoint));

        // Build observation
        Map<String, String> attrs = new HashMap<>();
        attrs.put("exchangeId", exchange.id().toString());
        attrs.put("host", host);
        attrs.put("path", path);
        attrs.put("httpMethod", httpMethod);
        attrs.put("responseStatusCode", String.valueOf(exchange.responseStatusCode()));
        attrs.put("operationType", detectedOpType);
        attrs.put("operationName", operationName);
        attrs.put("fieldCount", String.valueOf(topFields.size()));
        attrs.put("variableCount", String.valueOf(
                variablesNode != null && variablesNode.isObject() ? variablesNode.size() : 0));

        Instant observedAt = exchange.observedAt() == null ? Instant.now() : exchange.observedAt();
        String reqSummary = displayName + "(" + parameters.size() + " params)";
        String resSummary = "status=" + exchange.responseStatusCode();

        Observation observation = new Observation(UUID.randomUUID(), ProtocolKind.GRAPHQL,
                serviceId, endpointId, operationId, Optional.empty(), observedAt,
                Map.copyOf(attrs),
                Optional.of(reqSummary), Optional.of(resSummary));

        return List.of(new AnalysisResult(service, endpoint, operation, observation));
    }

    // ---- Variable parsing -------------------------------------------------

    private JsonNode parseVariables(HttpExchange exchange) {
        String body = exchange.requestBody().orElse("");
        if (body.isBlank()) return null;
        try {
            JsonNode root = objectMapper.readTree(body);
            if (root instanceof ObjectNode obj && obj.has("variables")) {
                JsonNode vars = obj.get("variables");
                return (vars != null && !vars.isNull() && vars.isObject()) ? vars : null;
            }
        } catch (JsonProcessingException ignored) {}
        return null;
    }

    private List<Parameter> buildVariableParameters(UUID operationId, JsonNode variablesNode) {
        List<Parameter> params = new ArrayList<>();
        if (variablesNode == null || !variablesNode.isObject()) return params;

        int count = 0;
        for (var it = variablesNode.fields(); it.hasNext() && count < MAX_FIELDS;) {
            var entry = it.next();
            String name = entry.getKey();
            if (name == null || name.isBlank()) continue;

            String paramPath = "$.variables." + name;
            UUID paramId = stableId("param", operationId + "|var|" + name);
            DataType type = inferDataType(paramId, "var", paramPath, name, entry.getValue(), 0);

            params.add(new Parameter(paramId, "$" + name, paramPath,
                    ParameterSource.GRAPHQL_VARIABLE, false, type, false, List.of()));
            count++;
        }
        return params;
    }

    // ---- Lightweight document parsing -------------------------------------

    /**
     * Parse top-level fields from a GraphQL selection set.
     * This is a conservative, regex-free parser that handles common cases.
     */
    static List<FieldInfo> parseTopLevelFields(String document) {
        if (document == null || document.isBlank()) return List.of();

        // Find the first top-level selection set opening brace
        int braceStart = findFirstSelectionSet(document);
        if (braceStart < 0) return List.of();

        String inside = extractBraceContent(document, braceStart);
        if (inside == null || inside.isBlank()) return List.of();

        return parseFields(inside);
    }

    private static int findFirstSelectionSet(String doc) {
        int depth = 0;
        boolean inString = false;
        boolean firstBraceFound = false;

        for (int i = 0; i < doc.length(); i++) {
            char ch = doc.charAt(i);
            if (ch == '#' && !inString) {
                int nl = doc.indexOf('\n', i);
                if (nl < 0) return -1;
                i = nl;
                continue;
            }
            if (ch == '"') { inString = !inString; continue; }
            if (inString) continue;
            if (ch == '(') { depth++; continue; }
            if (ch == ')') { depth--; continue; }
            if (ch == '{' && depth == 0) {
                if (!firstBraceFound) {
                    // For shorthand query, this IS the selection set
                    // For named operations, skip keyword/name/vars and find first {
                    firstBraceFound = true;
                    return i;
                }
            }
        }
        return -1;
    }

    private static String extractBraceContent(String doc, int openBrace) {
        int depth = 0;
        for (int i = openBrace; i < doc.length(); i++) {
            char ch = doc.charAt(i);
            if (ch == '{') depth++;
            else if (ch == '}') {
                depth--;
                if (depth == 0) {
                    return doc.substring(openBrace + 1, i).trim();
                }
            }
        }
        // Unclosed brace — return what we have
        return doc.substring(openBrace + 1).trim();
    }

    private static List<FieldInfo> parseFields(String content) {
        List<FieldInfo> fields = new ArrayList<>();
        int i = 0;
        while (i < content.length() && fields.size() < MAX_FIELDS) {
            // Skip whitespace, commas, comments
            while (i < content.length()) {
                char ch = content.charAt(i);
                if (Character.isWhitespace(ch) || ch == ',') { i++; continue; }
                if (ch == '#') {
                    int nl = content.indexOf('\n', i);
                    i = nl < 0 ? content.length() : nl + 1;
                    continue;
                }
                break;
            }
            if (i >= content.length()) break;

            // Skip fragment spread: ...FragmentName or inline fragment: ... on Type
            if (content.startsWith("...", i)) {
                i = skipToNextField(content, i + 3);
                continue;
            }

            // Read field name (possibly aliased: alias: fieldName)
            StringBuilder token = new StringBuilder();
            while (i < content.length() && isIdentChar(content.charAt(i))) {
                token.append(content.charAt(i)); i++;
            }
            if (token.isEmpty()) { i++; continue; }

            String fieldName = token.toString();

            // Check for alias
            i = skipWhitespace(content, i);
            if (i < content.length() && content.charAt(i) == ':') {
                i++; // skip ':'
                i = skipWhitespace(content, i);
                StringBuilder actualName = new StringBuilder();
                while (i < content.length() && isIdentChar(content.charAt(i))) {
                    actualName.append(content.charAt(i)); i++;
                }
                if (!actualName.isEmpty()) fieldName = actualName.toString();
            }

            // Parse arguments if present
            i = skipWhitespace(content, i);
            Map<String, String> args = new LinkedHashMap<>();
            if (i < content.length() && content.charAt(i) == '(') {
                int argEnd = findMatchingParen(content, i);
                if (argEnd > i) {
                    args = parseArguments(content.substring(i + 1, argEnd));
                    i = argEnd + 1;
                }
            }

            // Skip nested selection set
            i = skipWhitespace(content, i);
            boolean hasSubfields = false;
            if (i < content.length() && content.charAt(i) == '{') {
                hasSubfields = true;
                i = skipBraces(content, i);
            }

            // Skip directives (@skip, @include, etc.)
            i = skipWhitespace(content, i);
            if (i < content.length() && content.charAt(i) == '@') {
                i = skipToNextField(content, i);
            }

            fields.add(new FieldInfo(fieldName, args, hasSubfields));
        }
        return List.copyOf(fields);
    }

    // ---- Argument parsing --------------------------------------------------

    private static Map<String, String> parseArguments(String argContent) {
        Map<String, String> args = new LinkedHashMap<>();
        if (argContent == null || argContent.isBlank()) return args;

        int i = 0;
        while (i < argContent.length() && args.size() < MAX_FIELDS) {
            i = skipWhitespace(argContent, i);
            if (i >= argContent.length()) break;

            // Read argument name
            StringBuilder name = new StringBuilder();
            while (i < argContent.length() && isIdentChar(argContent.charAt(i))) {
                name.append(argContent.charAt(i)); i++;
            }
            if (name.isEmpty()) { i++; continue; }

            i = skipWhitespace(argContent, i);
            if (i >= argContent.length() || argContent.charAt(i) != ':') continue;
            i++; // skip ':'
            i = skipWhitespace(argContent, i);

            // Read value (simplified: capture until , or end)
            StringBuilder value = new StringBuilder();
            int depth = 0;
            boolean inStr = false;
            while (i < argContent.length()) {
                char ch = argContent.charAt(i);
                if (ch == '"') inStr = !inStr;
                if (!inStr) {
                    if (ch == '{' || ch == '[') depth++;
                    else if (ch == '}' || ch == ']') depth--;
                    else if (ch == ',' && depth == 0) break;
                }
                value.append(ch); i++;
            }
            if (i < argContent.length() && argContent.charAt(i) == ',') i++;

            args.put(name.toString(), value.toString().trim());
        }
        return args;
    }

    // ---- Type inference from runtime values --------------------------------

    private DataType inferDataType(UUID opId, String role, String path, String name, JsonNode node, int depth) {
        if (node == null || node.isMissingNode() || node.isNull()) return DataType.unknown(name);
        if (depth >= MAX_TYPE_DEPTH) return DataType.unknown(name);

        UUID typeId = stableId("datatype", opId + "|" + role + "|" + path);

        if (node.isObject()) {
            Map<String, DataType> fields = new LinkedHashMap<>();
            int count = 0;
            for (var it = node.fields(); it.hasNext() && count < MAX_FIELDS;) {
                var entry = it.next();
                if (entry.getKey() == null || entry.getKey().isBlank()) continue;
                fields.put(entry.getKey(), inferDataType(opId, role, path + "." + entry.getKey(),
                        entry.getKey(), entry.getValue(), depth + 1));
                count++;
            }
            return new DataType(typeId, name, DataTypeKind.OBJECT, ConfidenceLevel.LOW,
                    Map.copyOf(fields), Optional.empty(), List.of(), List.of(), List.of());
        }

        if (node.isArray()) {
            DataType elemType = null;
            for (JsonNode item : node) {
                if (item != null && !item.isNull()) {
                    elemType = inferDataType(opId, role, path + "[]", "Element", item, depth + 1);
                    break;
                }
            }
            return new DataType(typeId, name, DataTypeKind.ARRAY, ConfidenceLevel.LOW,
                    Map.of(), Optional.ofNullable(elemType), List.of(), List.of(), List.of());
        }

        return new DataType(typeId, scalarName(node), DataTypeKind.SCALAR, ConfidenceLevel.LOW,
                Map.of(), Optional.empty(), List.of(), List.of(), List.of());
    }

    private static DataType inferScalarType(UUID typeId, String rawValue) {
        if (rawValue == null || rawValue.isBlank()) return DataType.unknown("unknown");
        String v = rawValue.trim();
        if (v.startsWith("$")) {
            return new DataType(typeId, "variable", DataTypeKind.SCALAR, ConfidenceLevel.LOW,
                    Map.of(), Optional.empty(), List.of(), List.of(), List.of());
        }
        String name = "string";
        if ("true".equals(v) || "false".equals(v)) name = "boolean";
        else if ("null".equals(v)) name = "null";
        else if (v.matches("-?\\d+")) name = "integer";
        else if (v.matches("-?\\d+\\.\\d+")) name = "number";
        else if (v.startsWith("{")) name = "object";
        else if (v.startsWith("[")) name = "array";

        return new DataType(typeId, name, DataTypeKind.SCALAR, ConfidenceLevel.LOW,
                Map.of(), Optional.empty(), List.of(), List.of(), List.of());
    }

    // ---- Selection set to response type -----------------------------------

    private static DataType buildSelectionSetType(UUID opId, String opName, List<FieldInfo> fields) {
        if (fields.isEmpty()) return null;
        Map<String, DataType> fieldTypes = new LinkedHashMap<>();
        for (FieldInfo f : fields) {
            UUID fieldTypeId = stableId("datatype", opId + "|response|" + f.name);
            DataTypeKind kind = f.hasSubfields ? DataTypeKind.OBJECT : DataTypeKind.SCALAR;
            fieldTypes.put(f.name, new DataType(fieldTypeId, f.name, kind, ConfidenceLevel.LOW,
                    Map.of(), Optional.empty(), List.of(), List.of(), List.of()));
        }
        return new DataType(stableId("datatype", opId + "|response"), opName + "Response",
                DataTypeKind.OBJECT, ConfidenceLevel.LOW, Map.copyOf(fieldTypes),
                Optional.empty(), List.of(), List.of(), List.of());
    }

    // ---- Helpers -----------------------------------------------------------

    private static OperationKind mapOperationKind(String opType) {
        if (opType == null) return OperationKind.UNKNOWN;
        return switch (opType.toLowerCase(Locale.ROOT)) {
            case "query" -> OperationKind.QUERY;
            case "mutation" -> OperationKind.MUTATION;
            case "subscription" -> OperationKind.SUBSCRIPTION;
            default -> OperationKind.UNKNOWN;
        };
    }

    private static String buildAnonymousName(String opType, List<FieldInfo> fields) {
        if (!fields.isEmpty()) return fields.get(0).name;
        return opType.isBlank() ? "anonymous" : opType;
    }

    private static String scalarName(JsonNode node) {
        if (node.isTextual()) return "string";
        if (node.isBoolean()) return "boolean";
        if (node.isNumber()) return node.isIntegralNumber() ? "integer" : "number";
        return "scalar";
    }

    private static boolean isIdentChar(char ch) {
        return Character.isLetterOrDigit(ch) || ch == '_';
    }

    private static int skipWhitespace(String s, int i) {
        while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++;
        return i;
    }

    private static int skipBraces(String s, int start) {
        int depth = 0;
        for (int i = start; i < s.length(); i++) {
            if (s.charAt(i) == '{') depth++;
            else if (s.charAt(i) == '}') { depth--; if (depth == 0) return i + 1; }
        }
        return s.length();
    }

    private static int findMatchingParen(String s, int start) {
        int depth = 0;
        for (int i = start; i < s.length(); i++) {
            if (s.charAt(i) == '(') depth++;
            else if (s.charAt(i) == ')') { depth--; if (depth == 0) return i; }
        }
        return s.length() - 1;
    }

    private static int skipToNextField(String s, int start) {
        // Skip until we hit whitespace+identifier or end
        int i = start;
        while (i < s.length()) {
            char ch = s.charAt(i);
            if (ch == '{') { i = skipBraces(s, i); continue; }
            if (ch == '\n' || ch == ',') return i + 1;
            i++;
        }
        return i;
    }

    private static Set<String> extractContentTypes(Map<String, List<String>> headers) {
        if (headers == null) return Set.of();
        for (var entry : headers.entrySet()) {
            if (entry.getKey() != null && "content-type".equalsIgnoreCase(entry.getKey())) {
                Set<String> types = new HashSet<>();
                for (String v : entry.getValue()) {
                    if (v != null && !v.isBlank()) {
                        int semi = v.indexOf(';');
                        types.add((semi >= 0 ? v.substring(0, semi) : v).trim());
                    }
                }
                return Set.copyOf(types);
            }
        }
        return Set.of();
    }

    private static int effectivePort(String scheme, int port) {
        if (port > 0) return port;
        return "https".equals(scheme) ? 443 : ("http".equals(scheme) ? 80 : 0);
    }

    private static String normalizeHost(String h) { return h == null ? "" : h.trim().toLowerCase(Locale.ROOT); }
    private static String normalizePath(String p) {
        if (p == null || p.isBlank()) return "/";
        return p.trim().startsWith("/") ? p.trim() : "/" + p.trim();
    }

    private static UUID stableId(String ns, String key) {
        return UUID.nameUUIDFromBytes(((ns == null ? "" : ns) + ":" + (key == null ? "" : key))
                .getBytes(StandardCharsets.UTF_8));
    }

    /** Internal representation of a parsed top-level field. */
    record FieldInfo(String name, Map<String, String> arguments, boolean hasSubfields) {}

    /** Result of analyzing a single GraphQL exchange. */
    public record AnalysisResult(Service service, Endpoint endpoint, Operation operation, Observation observation) {
        public AnalysisResult {
            Objects.requireNonNull(service); Objects.requireNonNull(endpoint);
            Objects.requireNonNull(operation); Objects.requireNonNull(observation);
        }
    }
}
