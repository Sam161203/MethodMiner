import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

public final class JsonRpcRecord {
    private final String recordId;
    private final int messageId;
    private final Instant timestamp;
    private final String toolName;
    private final RequestData request;
    private final ResponseData response;

    public JsonRpcRecord(
            String recordId,
            int messageId,
            Instant timestamp,
            String toolName,
            RequestData request,
            ResponseData response
    ) {
        this.recordId = (recordId == null || recordId.isBlank()) ? UUID.randomUUID().toString() : recordId;
        this.messageId = messageId;
        this.timestamp = timestamp == null ? Instant.now() : timestamp;
        this.toolName = toolName == null ? "Unknown" : toolName;
        this.request = Objects.requireNonNull(request, "request must not be null");
        this.response = response == null ? ResponseData.missing() : response;
    }

    public String recordId() {
        return recordId;
    }

    public int messageId() {
        return messageId;
    }

    public Instant timestamp() {
        return timestamp;
    }

    public String toolName() {
        return toolName;
    }

    public RequestData request() {
        return request;
    }

    public ResponseData response() {
        return response;
    }

    public ObjectNode toJson(ObjectMapper mapper) {
        ObjectNode root = mapper.createObjectNode();
        root.put("recordId", recordId);
        root.put("messageId", messageId);
        root.put("timestamp", timestamp.toString());
        root.put("toolName", toolName);
        root.set("request", request.toJson(mapper));
        root.set("response", response.toJson(mapper));
        return root;
    }

    public static JsonRpcRecord fromJson(JsonNode node) {
        if (node == null || !node.isObject()) {
            throw new IllegalArgumentException("Raw record line is not a JSON object.");
        }

        String recordId = asText(node.get("recordId"), UUID.randomUUID().toString());
        int messageId = node.path("messageId").asInt(-1);
        Instant timestamp = parseInstant(node.path("timestamp").asText(), Instant.now());
        String toolName = asText(node.get("toolName"), "Unknown");

        RequestData request = RequestData.fromJson(node.path("request"));
        ResponseData response = ResponseData.fromJson(node.path("response"));

        return new JsonRpcRecord(recordId, messageId, timestamp, toolName, request, response);
    }

    private static String asText(JsonNode node, String fallback) {
        return node == null || node.isNull() ? fallback : node.asText(fallback);
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

    public record RequestData(
            String url,
            String httpMethod,
            List<String> headers,
            String bodyText,
            String bodyBase64,
            String rawHttpText,
            String rawHttpBase64
    ) {
        public RequestData {
            headers = immutableCopy(headers);
            url = url == null ? "" : url;
            httpMethod = httpMethod == null ? "" : httpMethod;
            bodyText = bodyText == null ? "" : bodyText;
            bodyBase64 = bodyBase64 == null ? "" : bodyBase64;
            rawHttpText = rawHttpText == null ? "" : rawHttpText;
            rawHttpBase64 = rawHttpBase64 == null ? "" : rawHttpBase64;
        }

        public ObjectNode toJson(ObjectMapper mapper) {
            ObjectNode node = mapper.createObjectNode();
            node.put("url", url);
            node.put("httpMethod", httpMethod);
            node.set("headers", toArray(mapper, headers));
            node.put("bodyText", bodyText);
            node.put("bodyBase64", bodyBase64);
            node.put("rawHttpText", rawHttpText);
            node.put("rawHttpBase64", rawHttpBase64);
            return node;
        }

        public static RequestData fromJson(JsonNode node) {
            if (node == null || !node.isObject()) {
                return new RequestData("", "", List.of(), "", "", "", "");
            }

            return new RequestData(
                    node.path("url").asText(""),
                    node.path("httpMethod").asText(""),
                    readStringArray(node.path("headers")),
                    node.path("bodyText").asText(""),
                    node.path("bodyBase64").asText(""),
                    node.path("rawHttpText").asText(""),
                    node.path("rawHttpBase64").asText("")
            );
        }

        public static RequestData fromCaptured(
                String url,
                String httpMethod,
                List<String> headers,
                String bodyText,
                byte[] bodyBytes,
                String rawHttpText,
                byte[] rawHttpBytes
        ) {
            return new RequestData(
                    url,
                    httpMethod,
                    headers,
                    bodyText,
                    toBase64(bodyBytes),
                    rawHttpText,
                    toBase64(rawHttpBytes)
            );
        }
    }

    public record ResponseData(
            boolean present,
            Integer statusCode,
            List<String> headers,
            String bodyText,
            String bodyBase64,
            String rawHttpText,
            String rawHttpBase64
    ) {
        public ResponseData {
            headers = immutableCopy(headers);
            bodyText = bodyText == null ? "" : bodyText;
            bodyBase64 = bodyBase64 == null ? "" : bodyBase64;
            rawHttpText = rawHttpText == null ? "" : rawHttpText;
            rawHttpBase64 = rawHttpBase64 == null ? "" : rawHttpBase64;
        }

        public static ResponseData missing() {
            return new ResponseData(false, null, List.of(), "", "", "", "");
        }

        public ObjectNode toJson(ObjectMapper mapper) {
            ObjectNode node = mapper.createObjectNode();
            node.put("present", present);
            if (statusCode == null) {
                node.putNull("statusCode");
            } else {
                node.put("statusCode", statusCode);
            }
            node.set("headers", toArray(mapper, headers));
            node.put("bodyText", bodyText);
            node.put("bodyBase64", bodyBase64);
            node.put("rawHttpText", rawHttpText);
            node.put("rawHttpBase64", rawHttpBase64);
            return node;
        }

        public static ResponseData fromJson(JsonNode node) {
            if (node == null || !node.isObject()) {
                return missing();
            }

            Integer statusCode = node.path("statusCode").isNumber() ? node.path("statusCode").asInt() : null;
            return new ResponseData(
                    node.path("present").asBoolean(false),
                    statusCode,
                    readStringArray(node.path("headers")),
                    node.path("bodyText").asText(""),
                    node.path("bodyBase64").asText(""),
                    node.path("rawHttpText").asText(""),
                    node.path("rawHttpBase64").asText("")
            );
        }

        public static ResponseData fromCaptured(
                Integer statusCode,
                List<String> headers,
                String bodyText,
                byte[] bodyBytes,
                String rawHttpText,
                byte[] rawHttpBytes
        ) {
            return new ResponseData(
                    true,
                    statusCode,
                    headers,
                    bodyText,
                    toBase64(bodyBytes),
                    rawHttpText,
                    toBase64(rawHttpBytes)
            );
        }
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
        List<String> values = new ArrayList<>();
        for (JsonNode item : node) {
            values.add(item.isNull() ? "" : item.asText(""));
        }
        return Collections.unmodifiableList(values);
    }

    private static List<String> immutableCopy(List<String> input) {
        if (input == null || input.isEmpty()) {
            return List.of();
        }
        List<String> copy = new ArrayList<>(input.size());
        for (String item : input) {
            copy.add(item == null ? "" : item);
        }
        return Collections.unmodifiableList(copy);
    }

    private static String toBase64(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return "";
        }
        return Base64.getEncoder().encodeToString(bytes);
    }
}
