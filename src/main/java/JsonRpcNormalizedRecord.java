import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public final class JsonRpcNormalizedRecord {
    private final String recordId;
    private final Instant timestamp;
    private final String methodName;
    private final String typeName;
    private final String url;
    private final String httpMethod;
    private final List<String> topLevelKeys;
    private final List<String> parameterKeys;
    private final List<String> nestedMethods;
    private final String paramsKind;
    private final String paramsMode;
    private final int paramsArraySize;
    private final boolean emptyParams;
    private final String idType;
    private final String rpcVersion;
    private final boolean batchRequest;
    private final boolean notificationRequest;
    private final String paramShapeSignature;
    private final String responseShapeSignature;
    private final String variantSignature;
    private final Integer responseStatus;
    private final int responseBodySize;
    private final boolean largeResponse;

    public JsonRpcNormalizedRecord(
            String recordId,
            Instant timestamp,
            String methodName,
            String typeName,
            String url,
            String httpMethod,
            List<String> topLevelKeys,
            List<String> parameterKeys,
            List<String> nestedMethods,
            String paramsKind,
            String paramsMode,
            int paramsArraySize,
            boolean emptyParams,
            String idType,
            String rpcVersion,
            boolean batchRequest,
            boolean notificationRequest,
            String paramShapeSignature,
            String responseShapeSignature,
            String variantSignature,
            Integer responseStatus,
            int responseBodySize,
            boolean largeResponse
    ) {
        this.recordId = recordId;
        this.timestamp = timestamp;
        this.methodName = methodName;
        this.typeName = typeName == null ? "" : typeName;
        this.url = url;
        this.httpMethod = httpMethod;
        this.topLevelKeys = immutableCopy(topLevelKeys);
        this.parameterKeys = immutableCopy(parameterKeys);
        this.nestedMethods = immutableCopy(nestedMethods);
        this.paramsKind = paramsKind;
        this.paramsMode = paramsMode == null ? "unknown" : paramsMode;
        this.paramsArraySize = paramsArraySize;
        this.emptyParams = emptyParams;
        this.idType = idType;
        this.rpcVersion = rpcVersion == null || rpcVersion.isBlank() ? "2.0" : rpcVersion;
        this.batchRequest = batchRequest;
        this.notificationRequest = notificationRequest;
        this.paramShapeSignature = paramShapeSignature;
        this.responseShapeSignature = responseShapeSignature;
        this.variantSignature = variantSignature;
        this.responseStatus = responseStatus;
        this.responseBodySize = responseBodySize;
        this.largeResponse = largeResponse;
    }

    public String recordId() {
        return recordId;
    }

    public Instant timestamp() {
        return timestamp;
    }

    public String methodName() {
        return methodName;
    }

    public String typeName() {
        return typeName;
    }

    public String url() {
        return url;
    }

    public String httpMethod() {
        return httpMethod;
    }

    public List<String> topLevelKeys() {
        return topLevelKeys;
    }

    public List<String> parameterKeys() {
        return parameterKeys;
    }

    public List<String> nestedMethods() {
        return nestedMethods;
    }

    public String paramsKind() {
        return paramsKind;
    }

    public String paramsMode() {
        return paramsMode;
    }

    public int paramsArraySize() {
        return paramsArraySize;
    }

    public boolean emptyParams() {
        return emptyParams;
    }

    public String idType() {
        return idType;
    }

    public String rpcVersion() {
        return rpcVersion;
    }

    public boolean batchRequest() {
        return batchRequest;
    }

    public boolean notificationRequest() {
        return notificationRequest;
    }

    public String paramShapeSignature() {
        return paramShapeSignature;
    }

    public String responseShapeSignature() {
        return responseShapeSignature;
    }

    public String variantSignature() {
        return variantSignature;
    }

    public Integer responseStatus() {
        return responseStatus;
    }

    public int responseBodySize() {
        return responseBodySize;
    }

    public boolean largeResponse() {
        return largeResponse;
    }

    public ObjectNode toJson(ObjectMapper mapper) {
        ObjectNode node = mapper.createObjectNode();
        node.put("recordId", recordId);
        node.put("timestamp", timestamp.toString());
        node.put("methodName", methodName);
        node.put("typeName", typeName);
        node.put("url", url);
        node.put("httpMethod", httpMethod);
        node.set("topLevelKeys", toArray(mapper, topLevelKeys));
        node.set("parameterKeys", toArray(mapper, parameterKeys));
        node.set("nestedMethods", toArray(mapper, nestedMethods));
        node.put("paramsKind", paramsKind);
        node.put("paramsMode", paramsMode);
        node.put("paramsArraySize", paramsArraySize);
        node.put("emptyParams", emptyParams);
        node.put("idType", idType);
        node.put("rpcVersion", rpcVersion);
        node.put("batchRequest", batchRequest);
        node.put("notificationRequest", notificationRequest);
        node.put("paramShapeSignature", paramShapeSignature);
        node.put("responseShapeSignature", responseShapeSignature);
        node.put("variantSignature", variantSignature);

        if (responseStatus == null) {
            node.putNull("responseStatus");
        } else {
            node.put("responseStatus", responseStatus);
        }

        node.put("responseBodySize", responseBodySize);
        node.put("largeResponse", largeResponse);
        return node;
    }

    public static JsonRpcNormalizedRecord fromJson(JsonNode node) {
        if (node == null || !node.isObject()) {
            throw new IllegalArgumentException("Normalized record line is not a JSON object.");
        }

        Instant timestamp = parseInstant(node.path("timestamp").asText(), Instant.now());
        Integer responseStatus = node.path("responseStatus").isNumber() ? node.path("responseStatus").asInt() : null;

        return new JsonRpcNormalizedRecord(
                node.path("recordId").asText(""),
                timestamp,
                node.path("methodName").asText(""),
            node.path("typeName").asText(""),
                node.path("url").asText(""),
                node.path("httpMethod").asText(""),
                readStringArray(node.path("topLevelKeys")),
                readStringArray(node.path("parameterKeys")),
            readStringArray(node.path("nestedMethods")),
                node.path("paramsKind").asText("unknown"),
            node.path("paramsMode").asText("unknown"),
                node.path("paramsArraySize").asInt(0),
                node.path("emptyParams").asBoolean(false),
                node.path("idType").asText("missing"),
            node.path("rpcVersion").asText("2.0"),
            node.path("batchRequest").asBoolean(false),
            node.path("notificationRequest").asBoolean(false),
                node.path("paramShapeSignature").asText("unknown"),
                node.path("responseShapeSignature").asText("missing"),
                node.path("variantSignature").asText("unknown"),
                responseStatus,
                node.path("responseBodySize").asInt(0),
                node.path("largeResponse").asBoolean(false)
        );
    }

    private static List<String> immutableCopy(List<String> values) {
        if (values == null || values.isEmpty()) {
            return List.of();
        }
        List<String> copy = new ArrayList<>(values.size());
        for (String value : values) {
            copy.add(value == null ? "" : value);
        }
        return Collections.unmodifiableList(copy);
    }

    private static ArrayNode toArray(ObjectMapper mapper, List<String> values) {
        ArrayNode array = mapper.createArrayNode();
        for (String value : values) {
            array.add(value == null ? "" : value);
        }
        return array;
    }

    private static List<String> readStringArray(JsonNode node) {
        if (node == null || !node.isArray()) {
            return List.of();
        }
        List<String> result = new ArrayList<>();
        for (JsonNode item : node) {
            result.add(item.isNull() ? "" : item.asText(""));
        }
        return Collections.unmodifiableList(result);
    }

    private static Instant parseInstant(String value, Instant fallback) {
        if (value == null || value.isBlank()) {
            return fallback;
        }
        try {
            return Instant.parse(value);
        } catch (DateTimeParseException ignored) {
            return fallback;
        }
    }
}
