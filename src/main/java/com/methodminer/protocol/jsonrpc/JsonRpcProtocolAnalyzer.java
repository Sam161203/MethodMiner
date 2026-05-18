package com.methodminer.protocol.jsonrpc;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.methodminer.core.model.ConfidenceLevel;
import com.methodminer.core.model.DataType;
import com.methodminer.core.model.DataTypeKind;
import com.methodminer.core.model.Endpoint;
import com.methodminer.core.model.Observation;
import com.methodminer.core.model.Operation;
import com.methodminer.core.model.OperationKind;
import com.methodminer.core.model.Parameter;
import com.methodminer.core.model.ParameterSource;
import com.methodminer.core.model.Service;
import com.methodminer.protocol.DetectionResult;
import com.methodminer.protocol.HttpExchange;
import com.methodminer.protocol.ProtocolKind;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

/**
 * Passive JSON-RPC analyzer that creates protocol-agnostic surface model objects.
 */
public final class JsonRpcProtocolAnalyzer {
    private static final int MAX_TYPE_DEPTH = 6;
    private static final int MAX_FIELDS_PER_OBJECT = 64;
    private static final int MAX_SHAPE_DEPTH = 5;
    private static final int MAX_SHAPE_FIELDS = 32;

    private final ObjectMapper objectMapper;

    public JsonRpcProtocolAnalyzer(ObjectMapper objectMapper) {
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper");
    }

    public List<AnalysisResult> analyze(HttpExchange exchange, DetectionResult detection) {
        Objects.requireNonNull(exchange, "exchange");
        Objects.requireNonNull(detection, "detection");

        if (detection.kind() != ProtocolKind.JSON_RPC) {
            return List.of();
        }

        JsonNode requestRoot = parseJson(exchange.requestBody().orElse(""));
        if (requestRoot == null) {
            return List.of();
        }

        List<RequestCall> calls = parseCalls(requestRoot);
        if (calls.isEmpty()) {
            return List.of();
        }

        JsonNode responseRoot = parseJson(exchange.responseBody().orElse(""));
        ParsedResponses responses = parseResponses(responseRoot);

        String host = normalizeHost(exchange.uri().getHost());
        String scheme = exchange.uri().getScheme() == null ? "" : exchange.uri().getScheme().toLowerCase(Locale.ROOT);
        int port = effectivePort(scheme, exchange.uri().getPort());
        String path = normalizePath(exchange.uri().getPath());
        String httpMethod = normalizeMethod(exchange.method());
        Set<String> contentTypes = extractContentTypes(exchange.requestHeaders());

        String serviceKey = scheme + "://" + host + ":" + port;
        UUID serviceId = stableId("service", serviceKey);
        UUID endpointId = stableId("endpoint", serviceKey + "|" + httpMethod + "|" + path + "|" + ProtocolKind.JSON_RPC);

        Service baseService = new Service(
                serviceId,
                host.isBlank() ? "(unknown host)" : host,
                host,
                "",
                List.of()
        );

        Instant observedAt = exchange.observedAt() == null ? Instant.now() : exchange.observedAt();

        List<AnalysisResult> results = new ArrayList<>(calls.size());
        for (RequestCall call : calls) {
            String methodName = call.methodName;
            if (methodName.isBlank()) {
                continue;
            }

            UUID operationId = stableId("operation", endpointId + "|" + methodName);
            String namespace = JsonRpcMethodName.namespaceOf(methodName);
            String simpleName = JsonRpcMethodName.simpleNameOf(methodName);

            ParamsAnalysis paramsAnalysis = analyzeParams(operationId, methodName, call.paramsNode);
            ResponseAnalysis responseAnalysis = analyzeResponse(operationId, methodName, call, responses);

            Operation operation = new Operation(
                    operationId,
                    ProtocolKind.JSON_RPC,
                    methodName,
                    OperationKind.METHOD,
                    paramsAnalysis.parameters,
                    Optional.ofNullable(paramsAnalysis.requestType),
                    Optional.ofNullable(responseAnalysis.responseType)
            );

            Endpoint endpoint = new Endpoint(
                    endpointId,
                    ProtocolKind.JSON_RPC,
                    httpMethod,
                    path,
                    contentTypes,
                    List.of(operation)
            );

            Service service = new Service(
                    baseService.id(),
                    baseService.name(),
                    baseService.host(),
                    baseService.basePath(),
                    List.of(endpoint)
            );

            Map<String, String> attributes = new HashMap<>();
            attributes.put("exchangeId", exchange.id().toString());
            attributes.put("host", host);
            attributes.put("path", path);
            attributes.put("httpMethod", httpMethod);
            attributes.put("responseStatusCode", String.valueOf(exchange.responseStatusCode()));
            attributes.put("confidence", String.valueOf(detection.confidence()));

            attributes.put("methodName", methodName);
            if (!namespace.isBlank()) {
                attributes.put("namespace", namespace);
            }
            if (!simpleName.isBlank()) {
                attributes.put("methodSimpleName", simpleName);
            }
            attributes.put("batch", String.valueOf(call.batch));
            attributes.put("notification", String.valueOf(call.notification));
            attributes.put("jsonrpcVersion", call.jsonrpcVersion);
            attributes.put("paramsMode", paramsAnalysis.paramsMode);
            attributes.put("paramCount", String.valueOf(paramsAnalysis.parameters.size()));
            attributes.put("requestIdType", call.idType);
            attributes.put("hasResult", String.valueOf(responseAnalysis.hasResult));
            attributes.put("hasError", String.valueOf(responseAnalysis.hasError));
            if (!responseAnalysis.resultShape.isBlank()) {
                attributes.put("resultShape", responseAnalysis.resultShape);
            }
            if (!responseAnalysis.errorShape.isBlank()) {
                attributes.put("errorShape", responseAnalysis.errorShape);
            }

            String requestSummary = buildRequestSummary(methodName, paramsAnalysis);
            String responseSummary = buildResponseSummary(exchange.responseStatusCode(), responseAnalysis);

            Observation observation = new Observation(
                    UUID.randomUUID(),
                    ProtocolKind.JSON_RPC,
                    serviceId,
                    endpointId,
                    operationId,
                    Optional.empty(),
                    observedAt,
                    Map.copyOf(attributes),
                    requestSummary.isBlank() ? Optional.empty() : Optional.of(requestSummary),
                    responseSummary.isBlank() ? Optional.empty() : Optional.of(responseSummary)
            );

            results.add(new AnalysisResult(service, endpoint, operation, observation));
        }

        return List.copyOf(results);
    }

    private JsonNode parseJson(String text) {
        if (text == null || text.isBlank()) {
            return null;
        }
        if (!looksLikeJson(text)) {
            return null;
        }
        try {
            return objectMapper.readTree(text);
        } catch (JsonProcessingException ignored) {
            return null;
        }
    }

    private static List<RequestCall> parseCalls(JsonNode requestRoot) {
        if (requestRoot == null || requestRoot.isNull() || requestRoot.isMissingNode()) {
            return List.of();
        }

        List<RequestCall> calls = new ArrayList<>();
        if (requestRoot instanceof ObjectNode objectNode) {
            RequestCall call = parseCall(objectNode, false);
            if (call != null) {
                calls.add(call);
            }
        } else if (requestRoot.isArray()) {
            for (JsonNode item : requestRoot) {
                if (item instanceof ObjectNode objectNode) {
                    RequestCall call = parseCall(objectNode, true);
                    if (call != null) {
                        calls.add(call);
                    }
                }
            }
        }
        return List.copyOf(calls);
    }

    private static RequestCall parseCall(ObjectNode callNode, boolean batch) {
        JsonNode methodNode = callNode.get("method");
        if (methodNode == null || methodNode.isNull()) {
            return null;
        }

        String methodName = methodNode.isTextual() ? methodNode.asText("") : methodNode.toString();
        methodName = methodName == null ? "" : methodName.trim();
        if (methodName.isBlank()) {
            return null;
        }

        JsonNode paramsNode = callNode.get("params");
        JsonNode idNode = callNode.get("id");
        boolean notification = idNode == null || idNode.isNull() || idNode.isMissingNode();

        String jsonrpcVersion = "2.0";
        JsonNode jsonrpcNode = callNode.get("jsonrpc");
        if (jsonrpcNode != null && !jsonrpcNode.isNull() && !jsonrpcNode.isMissingNode()) {
            String version = jsonrpcNode.isTextual() ? jsonrpcNode.asText("2.0") : jsonrpcNode.toString();
            if (version != null && !version.isBlank()) {
                jsonrpcVersion = version.trim();
            }
        }

        return new RequestCall(callNode, methodName, paramsNode, idNode, notification, jsonrpcVersion, batch, jsonType(idNode));
    }

    private static ParsedResponses parseResponses(JsonNode responseRoot) {
        if (responseRoot == null || responseRoot.isNull() || responseRoot.isMissingNode()) {
            return new ParsedResponses(null, Map.of());
        }

        if (responseRoot instanceof ObjectNode objectNode) {
            return new ParsedResponses(objectNode, Map.of());
        }

        if (responseRoot.isArray()) {
            Map<String, ObjectNode> byId = new LinkedHashMap<>();
            for (JsonNode item : responseRoot) {
                if (item instanceof ObjectNode objectNode) {
                    String key = idKey(objectNode.get("id"));
                    if (!key.isBlank()) {
                        byId.putIfAbsent(key, objectNode);
                    }
                }
            }
            return new ParsedResponses(null, Map.copyOf(byId));
        }

        return new ParsedResponses(null, Map.of());
    }

    private ResponseAnalysis analyzeResponse(UUID operationId, String methodName, RequestCall call, ParsedResponses responses) {
        ObjectNode response = null;
        if (!call.notification) {
            String key = idKey(call.idNode);
            if (!key.isBlank()) {
                response = responses.responsesById.get(key);
            }
        }
        if (response == null) {
            response = responses.singleResponse;
        }

        JsonNode resultNode = response == null ? null : response.get("result");
        JsonNode errorNode = response == null ? null : response.get("error");

        boolean hasResult = resultNode != null && !resultNode.isMissingNode() && !resultNode.isNull();
        boolean hasError = errorNode != null && !errorNode.isMissingNode() && !errorNode.isNull();

        DataType resultType = hasResult
                ? inferDataType(operationId, "result", "$.result", methodName + "Result", resultNode, 0)
                : null;
        DataType errorType = hasError
                ? inferDataType(operationId, "error", "$.error", methodName + "Error", errorNode, 0)
                : null;

        DataType responseType = null;
        if (resultType != null && errorType != null) {
            responseType = new DataType(
                    stableId("datatype", operationId + "|response|union"),
                    methodName + "Response",
                    DataTypeKind.UNION,
                    ConfidenceLevel.LOW,
                    Map.of(),
                    Optional.empty(),
                    List.of(resultType, errorType),
                    List.of(),
                    List.of()
            );
        } else if (resultType != null) {
            responseType = resultType;
        } else if (errorType != null) {
            responseType = errorType;
        }

        String resultShape = hasResult ? shapeSignature(resultNode, 0) : "";
        String errorShape = hasError ? shapeSignature(errorNode, 0) : "";

        return new ResponseAnalysis(hasResult, hasError, responseType, resultShape, errorShape);
    }

    private ParamsAnalysis analyzeParams(UUID operationId, String methodName, JsonNode paramsNode) {
        String paramsMode = detectParamsMode(paramsNode);
        List<Parameter> parameters = new ArrayList<>();
        DataType requestType = null;

        if (paramsNode == null || paramsNode.isMissingNode() || paramsNode.isNull()) {
            return new ParamsAnalysis(paramsMode, List.of(), null);
        }

        if (paramsNode.isObject()) {
            Map<String, DataType> fields = new LinkedHashMap<>();
            int count = 0;
            for (var it = paramsNode.fields(); it.hasNext() && count < MAX_FIELDS_PER_OBJECT; ) {
                var entry = it.next();
                String name = entry.getKey() == null ? "" : entry.getKey();
                if (name.isBlank()) {
                    continue;
                }
                JsonNode value = entry.getValue();
                String path = "$.params." + name;
                DataType type = inferDataType(operationId, "param", path, name, value, 0);
                fields.put(name, type);

                parameters.add(new Parameter(
                        stableId("param", operationId + "|" + name),
                        name,
                        path,
                        ParameterSource.JSON_RPC_PARAM,
                        false,
                        type,
                        false,
                        List.of()
                ));
                count++;
            }

            requestType = new DataType(
                    stableId("datatype", operationId + "|params|object"),
                    methodName + "Params",
                    DataTypeKind.OBJECT,
                    ConfidenceLevel.LOW,
                    Map.copyOf(fields),
                    Optional.empty(),
                    List.of(),
                    List.of(),
                    List.of()
            );
        } else if (paramsNode.isArray()) {
            List<DataType> elementTypes = new ArrayList<>();
            for (int i = 0; i < paramsNode.size(); i++) {
                JsonNode value = paramsNode.get(i);
                String name = "arg[" + i + "]";
                String path = "$.params[" + i + "]";
                DataType type = inferDataType(operationId, "param", path, name, value, 0);
                parameters.add(new Parameter(
                        stableId("param", operationId + "|" + name),
                        name,
                        path,
                        ParameterSource.JSON_RPC_PARAM,
                        false,
                        type,
                        false,
                        List.of()
                ));
                elementTypes.add(type);
            }

            DataType elementType = mergeArrayElementTypes(operationId, elementTypes);
            requestType = new DataType(
                    stableId("datatype", operationId + "|params|array"),
                    methodName + "Params",
                    DataTypeKind.ARRAY,
                    ConfidenceLevel.LOW,
                    Map.of(),
                    Optional.ofNullable(elementType),
                    List.of(),
                    List.of(),
                    List.of()
            );
        } else {
            DataType type = inferDataType(operationId, "param", "$.params", "value", paramsNode, 0);
            parameters.add(new Parameter(
                    stableId("param", operationId + "|value"),
                    "value",
                    "$.params",
                    ParameterSource.JSON_RPC_PARAM,
                    false,
                    type,
                    false,
                    List.of()
            ));

            requestType = new DataType(
                    stableId("datatype", operationId + "|params|scalar"),
                    methodName + "Params",
                    type.kind(),
                    ConfidenceLevel.LOW,
                    Map.of(),
                    type.elementType(),
                    type.variants(),
                    type.enumValues(),
                    List.of()
            );
        }

        return new ParamsAnalysis(paramsMode, List.copyOf(parameters), requestType);
    }

    private static DataType mergeArrayElementTypes(UUID operationId, List<DataType> elementTypes) {
        if (elementTypes == null || elementTypes.isEmpty()) {
            return null;
        }

        DataType first = elementTypes.get(0);
        boolean allSame = true;
        for (DataType type : elementTypes) {
            if (type == null) {
                continue;
            }
            if (!Objects.equals(type.kind(), first.kind())) {
                allSame = false;
                break;
            }
        }

        if (allSame) {
            return first;
        }

        List<DataType> variants = new ArrayList<>();
        for (DataType type : elementTypes) {
            if (type == null) {
                continue;
            }
            boolean exists = false;
            for (DataType v : variants) {
                if (v.id().equals(type.id())) {
                    exists = true;
                    break;
                }
            }
            if (!exists) {
                variants.add(type);
            }
        }

        return new DataType(
                stableId("datatype", operationId + "|params|array|element|union"),
                "Element",
                DataTypeKind.UNION,
                ConfidenceLevel.LOW,
                Map.of(),
                Optional.empty(),
                List.copyOf(variants),
                List.of(),
                List.of()
        );
    }

    private static DataType inferDataType(
            UUID operationId,
            String role,
            String path,
            String name,
            JsonNode node,
            int depth
    ) {
        if (node == null || node.isMissingNode()) {
            return DataType.unknown(name);
        }
        if (node.isNull()) {
            return new DataType(
                    stableId("datatype", operationId + "|" + role + "|" + path),
                    "null",
                    DataTypeKind.SCALAR,
                    ConfidenceLevel.LOW,
                    Map.of(),
                    Optional.empty(),
                    List.of(),
                    List.of(),
                    List.of()
            );
        }

        if (depth >= MAX_TYPE_DEPTH) {
            return new DataType(
                    stableId("datatype", operationId + "|" + role + "|" + path),
                    name,
                    DataTypeKind.UNKNOWN,
                    ConfidenceLevel.LOW,
                    Map.of(),
                    Optional.empty(),
                    List.of(),
                    List.of(),
                    List.of()
            );
        }

        if (node.isObject()) {
            Map<String, DataType> fields = new LinkedHashMap<>();
            int count = 0;
            for (var it = node.fields(); it.hasNext() && count < MAX_FIELDS_PER_OBJECT; ) {
                var entry = it.next();
                String key = entry.getKey() == null ? "" : entry.getKey();
                if (key.isBlank()) {
                    continue;
                }
                String childPath = path + "." + key;
                fields.put(key, inferDataType(operationId, role, childPath, key, entry.getValue(), depth + 1));
                count++;
            }
            return new DataType(
                    stableId("datatype", operationId + "|" + role + "|" + path),
                    name,
                    DataTypeKind.OBJECT,
                    ConfidenceLevel.LOW,
                    Map.copyOf(fields),
                    Optional.empty(),
                    List.of(),
                    List.of(),
                    List.of()
            );
        }

        if (node.isArray()) {
            JsonNode firstNonNull = null;
            for (JsonNode item : node) {
                if (item != null && !item.isNull() && !item.isMissingNode()) {
                    firstNonNull = item;
                    break;
                }
            }

            DataType elementType = firstNonNull == null
                    ? null
                    : inferDataType(operationId, role, path + "[]", "Element", firstNonNull, depth + 1);

            return new DataType(
                    stableId("datatype", operationId + "|" + role + "|" + path),
                    name,
                    DataTypeKind.ARRAY,
                    ConfidenceLevel.LOW,
                    Map.of(),
                    Optional.ofNullable(elementType),
                    List.of(),
                    List.of(),
                    List.of()
            );
        }

        return new DataType(
                stableId("datatype", operationId + "|" + role + "|" + path),
                scalarName(node),
                DataTypeKind.SCALAR,
                ConfidenceLevel.LOW,
                Map.of(),
                Optional.empty(),
                List.of(),
                List.of(),
                List.of()
        );
    }

    private static String scalarName(JsonNode node) {
        if (node == null || node.isMissingNode()) {
            return "unknown";
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
        return "scalar";
    }

    private static String buildRequestSummary(String methodName, ParamsAnalysis paramsAnalysis) {
        String keys = "";
        if (!paramsAnalysis.parameters.isEmpty()) {
            List<String> names = new ArrayList<>();
            for (int i = 0; i < Math.min(paramsAnalysis.parameters.size(), 12); i++) {
                names.add(paramsAnalysis.parameters.get(i).name());
            }
            keys = String.join(",", names);
            if (paramsAnalysis.parameters.size() > 12) {
                keys += ",...";
            }
        }
        if (keys.isBlank()) {
            return methodName + "(" + paramsAnalysis.paramsMode + ")";
        }
        return methodName + "(" + paramsAnalysis.paramsMode + ":" + keys + ")";
    }

    private static String buildResponseSummary(int statusCode, ResponseAnalysis responseAnalysis) {
        String kind = responseAnalysis.hasError ? "error" : (responseAnalysis.hasResult ? "result" : "none");
        if (!responseAnalysis.resultShape.isBlank() && responseAnalysis.hasResult) {
            return "status=" + statusCode + " " + kind + " " + responseAnalysis.resultShape;
        }
        if (!responseAnalysis.errorShape.isBlank() && responseAnalysis.hasError) {
            return "status=" + statusCode + " " + kind + " " + responseAnalysis.errorShape;
        }
        return "status=" + statusCode + " " + kind;
    }

    private static String shapeSignature(JsonNode node, int depth) {
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
        if (depth >= MAX_SHAPE_DEPTH) {
            return node.isObject() ? "object{...}" : (node.isArray() ? "array[...]" : "value");
        }
        if (node.isArray()) {
            if (node.isEmpty()) {
                return "array[]";
            }
            return "array<" + shapeSignature(node.get(0), depth + 1) + ">";
        }
        if (node.isObject()) {
            List<String> parts = new ArrayList<>();
            int count = 0;
            for (var it = node.fields(); it.hasNext() && count < MAX_SHAPE_FIELDS; ) {
                var entry = it.next();
                String key = entry.getKey() == null ? "" : entry.getKey();
                if (key.isBlank()) {
                    continue;
                }
                parts.add(key + ":" + shapeSignature(entry.getValue(), depth + 1));
                count++;
            }
            if (itHasMore(node, count)) {
                parts.add("...");
            }
            return "object{" + String.join(",", parts) + "}";
        }
        return node.getNodeType().name().toLowerCase(Locale.ROOT);
    }

    private static boolean itHasMore(JsonNode node, int count) {
        if (node == null || !node.isObject()) {
            return false;
        }
        int total = 0;
        for (var it = node.fields(); it.hasNext(); ) {
            it.next();
            total++;
            if (total > count) {
                return true;
            }
        }
        return false;
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

    private static Set<String> extractContentTypes(Map<String, List<String>> headers) {
        if (headers == null || headers.isEmpty()) {
            return Set.of();
        }

        for (var entry : headers.entrySet()) {
            if (entry.getKey() == null) {
                continue;
            }
            if (!"content-type".equalsIgnoreCase(entry.getKey())) {
                continue;
            }

            Set<String> types = new HashSet<>();
            for (String value : entry.getValue()) {
                if (value == null || value.isBlank()) {
                    continue;
                }
                String normalized = value.trim();
                int semi = normalized.indexOf(';');
                if (semi >= 0) {
                    normalized = normalized.substring(0, semi).trim();
                }
                if (!normalized.isBlank()) {
                    types.add(normalized);
                }
            }
            return Set.copyOf(types);
        }

        return Set.of();
    }

    private static int effectivePort(String scheme, int port) {
        if (port > 0) {
            return port;
        }
        return switch (scheme) {
            case "https" -> 443;
            case "http" -> 80;
            default -> 0;
        };
    }

    private static String normalizeHost(String host) {
        if (host == null) {
            return "";
        }
        return host.trim().toLowerCase(Locale.ROOT);
    }

    private static String normalizePath(String path) {
        if (path == null || path.isBlank()) {
            return "/";
        }
        String trimmed = path.trim();
        return trimmed.startsWith("/") ? trimmed : "/" + trimmed;
    }

    private static String normalizeMethod(String method) {
        return method == null ? "" : method.trim().toUpperCase(Locale.ROOT);
    }

    private static UUID stableId(String namespace, String key) {
        String value = (namespace == null ? "" : namespace) + ":" + (key == null ? "" : key);
        return UUID.nameUUIDFromBytes(value.getBytes(StandardCharsets.UTF_8));
    }

    private static boolean looksLikeJson(String bodyText) {
        if (bodyText == null) {
            return false;
        }
        for (int i = 0; i < bodyText.length(); i++) {
            char ch = bodyText.charAt(i);
            if (ch == '\uFEFF' || Character.isWhitespace(ch)) {
                continue;
            }
            return ch == '{' || ch == '[';
        }
        return false;
    }

    private static String idKey(JsonNode idNode) {
        if (idNode == null || idNode.isMissingNode() || idNode.isNull()) {
            return "";
        }
        if (idNode.isTextual()) {
            return "s:" + idNode.asText("");
        }
        if (idNode.isIntegralNumber()) {
            return "i:" + idNode.asLong();
        }
        if (idNode.isNumber()) {
            return "n:" + idNode.asDouble();
        }
        if (idNode.isBoolean()) {
            return "b:" + idNode.asBoolean();
        }
        return "j:" + idNode.toString();
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

    public record AnalysisResult(Service service, Endpoint endpoint, Operation operation, Observation observation) {
        public AnalysisResult {
            service = Objects.requireNonNull(service, "service");
            endpoint = Objects.requireNonNull(endpoint, "endpoint");
            operation = Objects.requireNonNull(operation, "operation");
            observation = Objects.requireNonNull(observation, "observation");
        }
    }

    private record RequestCall(
            ObjectNode callNode,
            String methodName,
            JsonNode paramsNode,
            JsonNode idNode,
            boolean notification,
            String jsonrpcVersion,
            boolean batch,
            String idType
    ) {
    }

    private record ParsedResponses(ObjectNode singleResponse, Map<String, ObjectNode> responsesById) {
    }

    private record ParamsAnalysis(String paramsMode, List<Parameter> parameters, DataType requestType) {
    }

    private record ResponseAnalysis(
            boolean hasResult,
            boolean hasError,
            DataType responseType,
            String resultShape,
            String errorShape
    ) {
    }
}
