import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;

public final class JsonRpcParser {
    private final ObjectMapper objectMapper;
    private final int largeResponseThresholdBytes;

    public JsonRpcParser(ObjectMapper objectMapper, int largeResponseThresholdBytes) {
        this.objectMapper = objectMapper;
        this.largeResponseThresholdBytes = Math.max(largeResponseThresholdBytes, 1024);
    }

    public ProbeResult probeRequestBody(String bodyText) {
        if (bodyText == null || bodyText.isBlank()) {
            return ProbeResult.notCandidate("empty-body");
        }

        if (!looksLikeJson(bodyText)) {
            return ProbeResult.notCandidate("not-json");
        }

        final JsonNode root;
        try {
            root = objectMapper.readTree(bodyText);
        } catch (JsonProcessingException ex) {
            return ProbeResult.malformedJson(ex.getOriginalMessage());
        }

        RequestSummary summary = parseRequestSummary(root, false);
        if (summary.calls().isEmpty()) {
            return ProbeResult.notCandidate("missing-method");
        }

        return ProbeResult.candidate(summary.calls().get(0).methodName());
    }

    public JsonRpcNormalizedRecord normalize(JsonRpcRecord record) throws JsonProcessingException {
        return normalizeAll(record).get(0);
    }

    public List<JsonRpcNormalizedRecord> normalizeAll(JsonRpcRecord record) throws JsonProcessingException {
        JsonNode requestRoot = objectMapper.readTree(record.request().bodyText());
        final RequestSummary summary;
        try {
            summary = parseRequestSummary(requestRoot, true);
        } catch (IllegalArgumentException ex) {
            throw new JsonProcessingException(ex.getMessage()) {
            };
        }

        ResponseShape responseShape = responseShape(record.response());

        List<JsonRpcNormalizedRecord> normalizedRecords = new ArrayList<>();
        for (CallSummary call : summary.calls()) {
            normalizedRecords.add(buildNormalizedRecord(record, summary, call, responseShape, call.methodName(), ""));

            if (isMultiCallWrapper(call.methodName()) && !call.nestedMethods().isEmpty()) {
                for (String nestedMethod : call.nestedMethods()) {
                    if (nestedMethod == null || nestedMethod.isBlank()) {
                        continue;
                    }
                    normalizedRecords.add(buildNormalizedRecord(
                            record,
                            summary,
                            call,
                            responseShape,
                            nestedMethod,
                            "|expandedFrom=" + call.methodName()
                    ));
                }
            }
        }

        if (normalizedRecords.isEmpty()) {
            throw new JsonProcessingException("Request JSON has no valid JSON-RPC method calls") {
            };
        }

        return List.copyOf(normalizedRecords);
    }

    private JsonRpcNormalizedRecord buildNormalizedRecord(
            JsonRpcRecord record,
            RequestSummary summary,
            CallSummary call,
            ResponseShape responseShape,
            String methodName,
            String variantSuffix
    ) {
        JsonNode paramsNode = call.paramsNode();

        String paramsKind = JsonShapeUtil.topLevelType(paramsNode);
        int paramsArraySize = paramsNode != null && paramsNode.isArray() ? paramsNode.size() : 0;
        boolean emptyParams = JsonShapeUtil.isEmptyParams(paramsNode);
        List<String> topLevelKeys = JsonShapeUtil.objectKeys(call.callNode());
        List<String> parameterKeys = parameterKeys(paramsNode);

        String idType = JsonShapeUtil.topLevelType(call.callNode().path("id"));
        String paramShapeSignature = JsonShapeUtil.shapeSignature(paramsNode);

        String variantSignature = "rpc=" + summary.rpcVersion()
                + "|batch=" + summary.batchRequest()
                + "|notify=" + call.notificationRequest()
                + "|mode=" + call.paramsMode()
                + "|type=" + defaultIfBlank(call.typeName(), "none")
                + "|param=" + paramShapeSignature
                + "|response=" + responseShape.signature()
                + "|status=" + responseShape.statusCodeMarker()
                + "|keys=" + String.join(",", topLevelKeys)
                + (variantSuffix == null ? "" : variantSuffix);

        return new JsonRpcNormalizedRecord(
                record.recordId(),
                record.timestamp(),
                methodName,
                call.typeName(),
                record.request().url(),
                record.request().httpMethod(),
                topLevelKeys,
                parameterKeys,
                call.nestedMethods(),
                paramsKind,
                call.paramsMode(),
                paramsArraySize,
                emptyParams,
                idType,
                summary.rpcVersion(),
                summary.batchRequest(),
                call.notificationRequest(),
                paramShapeSignature,
                responseShape.signature(),
                variantSignature,
                responseShape.statusCode(),
                responseShape.bodySize(),
                responseShape.bodySize() >= largeResponseThresholdBytes
        );
    }

    private static boolean isMultiCallWrapper(String methodName) {
        if (methodName == null || methodName.isBlank()) {
            return false;
        }
        String lowered = methodName.toLowerCase(Locale.ROOT);
        return "executemulticall".equals(lowered) || lowered.contains("multicall");
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

    public ObjectNode parseObjectBody(String bodyText) throws JsonProcessingException {
        JsonNode node = objectMapper.readTree(bodyText);
        if (!(node instanceof ObjectNode objectNode)) {
            throw new JsonProcessingException("Expected JSON object body") {
            };
        }
        return objectNode;
    }

    private RequestSummary parseRequestSummary(JsonNode root, boolean strict) {
        if (root == null) {
            if (strict) {
                throw new IllegalArgumentException("Request JSON is missing");
            }
            return new RequestSummary(false, "2.0", List.of());
        }

        boolean batchRequest = root.isArray();
        List<CallSummary> calls = new ArrayList<>();

        if (root instanceof ObjectNode objectNode) {
            CallSummary call = parseCall(objectNode);
            if (call != null) {
                calls.add(call);
            }
        } else if (root.isArray()) {
            for (JsonNode item : root) {
                if (item instanceof ObjectNode objectNode) {
                    CallSummary call = parseCall(objectNode);
                    if (call != null) {
                        calls.add(call);
                    }
                }
            }
        } else {
            if (strict) {
                throw new IllegalArgumentException("Request JSON is neither an object nor an array");
            }
            return new RequestSummary(false, "2.0", List.of());
        }

        if (strict && calls.isEmpty()) {
            throw new IllegalArgumentException("Request JSON has no valid JSON-RPC method calls");
        }

        String rpcVersion = "2.0";
        for (CallSummary call : calls) {
            if (call.rpcVersion() != null && !call.rpcVersion().isBlank()) {
                rpcVersion = call.rpcVersion();
                break;
            }
        }

        return new RequestSummary(batchRequest, rpcVersion, List.copyOf(calls));
    }

    private CallSummary parseCall(ObjectNode callNode) {
        JsonNode methodNode = callNode.get("method");
        if (methodNode == null || methodNode.isNull()) {
            return null;
        }

        String methodName = methodNode.isTextual() ? methodNode.asText("") : methodNode.toString();
        if (methodName.isBlank()) {
            return null;
        }

        JsonNode paramsNode = callNode.get("params");
        if (paramsNode == null || paramsNode.isNull()) {
            return null;
        }

        String paramsMode = detectParamsMode(paramsNode);
        String typeName = findTypeName(paramsNode);
        boolean notification = !callNode.has("id") || callNode.path("id").isNull();

        String rpcVersion = callNode.path("jsonrpc").asText("2.0");
        List<String> nestedMethods = extractNestedMethods(methodName, paramsNode);

        return new CallSummary(callNode, methodName, paramsNode, paramsMode, typeName, rpcVersion, notification, nestedMethods);
    }

    private List<String> parameterKeys(JsonNode paramsNode) {
        if (paramsNode == null || paramsNode.isMissingNode() || paramsNode.isNull()) {
            return List.of();
        }

        if (paramsNode.isObject()) {
            return JsonShapeUtil.objectKeys(paramsNode);
        }

        if (paramsNode.isArray()) {
            List<String> positional = new ArrayList<>();
            for (int i = 0; i < paramsNode.size(); i++) {
                positional.add("arg[" + i + "]");
            }
            return List.copyOf(positional);
        }

        return List.of("value");
    }

    private String detectParamsMode(JsonNode paramsNode) {
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
        return JsonShapeUtil.topLevelType(paramsNode);
    }

    private String findTypeName(JsonNode paramsNode) {
        return findTypeNameRecursive(paramsNode, 0);
    }

    private String findTypeNameRecursive(JsonNode node, int depth) {
        if (node == null || node.isMissingNode() || node.isNull() || depth > 6) {
            return "";
        }

        if (node.isObject()) {
            for (Map.Entry<String, JsonNode> entry : iterable(node.fields())) {
                String key = entry.getKey() == null ? "" : entry.getKey().toLowerCase(Locale.ROOT);
                if ("typename".equals(key) || "type".equals(key) || "entitytype".equals(key)) {
                    JsonNode value = entry.getValue();
                    if (value != null && !value.isNull()) {
                        String text = value.asText("").trim();
                        if (!text.isBlank()) {
                            return text;
                        }
                    }
                }
            }

            for (Map.Entry<String, JsonNode> entry : iterable(node.fields())) {
                String nested = findTypeNameRecursive(entry.getValue(), depth + 1);
                if (!nested.isBlank()) {
                    return nested;
                }
            }
            return "";
        }

        if (node.isArray()) {
            for (int i = 0; i < Math.min(node.size(), 6); i++) {
                String nested = findTypeNameRecursive(node.get(i), depth + 1);
                if (!nested.isBlank()) {
                    return nested;
                }
            }
        }

        return "";
    }

    private List<String> extractNestedMethods(String methodName, JsonNode paramsNode) {
        if (methodName == null || methodName.isBlank()) {
            return List.of();
        }

        boolean wrapper = "executemulticall".equalsIgnoreCase(methodName)
                || methodName.toLowerCase(Locale.ROOT).contains("multicall");

        if (!wrapper && !containsNestedCallHints(paramsNode)) {
            return List.of();
        }

        LinkedHashSet<String> methods = new LinkedHashSet<>();
        collectNestedMethods(paramsNode, methods, 0);
        methods.remove(methodName);
        return List.copyOf(methods);
    }

    private boolean containsNestedCallHints(JsonNode paramsNode) {
        if (paramsNode == null || paramsNode.isMissingNode() || paramsNode.isNull()) {
            return false;
        }

        if (paramsNode.isObject()) {
            for (Map.Entry<String, JsonNode> entry : iterable(paramsNode.fields())) {
                String key = entry.getKey() == null ? "" : entry.getKey().toLowerCase(Locale.ROOT);
                if ("calls".equals(key)
                        || "requests".equals(key)
                        || "operations".equals(key)
                        || "methods".equals(key)
                        || key.contains("multicall")) {
                    return true;
                }
            }
        }

        return false;
    }

    private void collectNestedMethods(JsonNode node, LinkedHashSet<String> out, int depth) {
        if (node == null || node.isNull() || node.isMissingNode() || depth > 8) {
            return;
        }

        if (node.isObject()) {
            JsonNode methodNode = node.get("method");
            if (methodNode != null && !methodNode.isNull()) {
                String method = methodNode.isTextual() ? methodNode.asText("") : methodNode.toString();
                if (!method.isBlank()) {
                    out.add(method);
                }
            }

            for (Map.Entry<String, JsonNode> entry : iterable(node.fields())) {
                collectNestedMethods(entry.getValue(), out, depth + 1);
            }
            return;
        }

        if (node.isArray()) {
            for (JsonNode item : node) {
                collectNestedMethods(item, out, depth + 1);
            }
        }
    }

    private ResponseShape responseShape(JsonRpcRecord.ResponseData response) {
        if (response == null || !response.present()) {
            return new ResponseShape("missing-response", null, 0, "none");
        }

        Integer statusCode = response.statusCode();
        int bodySize = response.bodyBase64().isEmpty() ? 0 : response.bodyText().length();
        String statusMarker = statusCode == null ? "unknown" : String.valueOf(statusCode);

        if (response.bodyText() == null || response.bodyText().isBlank()) {
            return new ResponseShape("empty-response-body", statusCode, bodySize, statusMarker);
        }

        try {
            JsonNode parsed = objectMapper.readTree(response.bodyText());
            return new ResponseShape(JsonShapeUtil.shapeSignature(parsed), statusCode, bodySize, statusMarker);
        } catch (JsonProcessingException ex) {
            return new ResponseShape("non-json-response", statusCode, bodySize, statusMarker);
        }
    }

    private static String defaultIfBlank(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value;
    }

    private static <T> Iterable<T> iterable(java.util.Iterator<T> iterator) {
        return () -> iterator;
    }

    public enum ProbeKind {
        CANDIDATE,
        NOT_CANDIDATE,
        MALFORMED_JSON
    }

    public record ProbeResult(ProbeKind kind, String reason, String methodName, String error) {
        public static ProbeResult candidate(String methodName) {
            return new ProbeResult(ProbeKind.CANDIDATE, "ok", methodName, "");
        }

        public static ProbeResult notCandidate(String reason) {
            return new ProbeResult(ProbeKind.NOT_CANDIDATE, reason, "", "");
        }

        public static ProbeResult malformedJson(String error) {
            return new ProbeResult(ProbeKind.MALFORMED_JSON, "malformed-json", "", error == null ? "unknown json parse error" : error);
        }

        public boolean isCandidate() {
            return kind == ProbeKind.CANDIDATE;
        }

        public boolean isMalformedJson() {
            return kind == ProbeKind.MALFORMED_JSON;
        }
    }

    private record RequestSummary(boolean batchRequest, String rpcVersion, List<CallSummary> calls) {
    }

    private record CallSummary(
            ObjectNode callNode,
            String methodName,
            JsonNode paramsNode,
            String paramsMode,
            String typeName,
            String rpcVersion,
            boolean notificationRequest,
            List<String> nestedMethods
    ) {
    }

    private record ResponseShape(String signature, Integer statusCode, int bodySize, String statusCodeMarker) {
    }
}
