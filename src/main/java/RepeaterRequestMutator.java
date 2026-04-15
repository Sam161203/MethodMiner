import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.TextNode;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

public final class RepeaterRequestMutator {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private RepeaterRequestMutator() {
    }

    public static String mutateCredentialField(String rawHttpRequest, int callIndex, String credentialKey, String newValue) {
        return mutateRequestBody(rawHttpRequest, root -> {
            ObjectNode call = resolveCallNode(root, callIndex);
            if (call == null) {
                return false;
            }

            JsonNode params = call.path("params");
            if (!(params instanceof ObjectNode paramsObject)) {
                return false;
            }

            JsonNode credentials = paramsObject.path("credentials");
            if (credentials instanceof ObjectNode credentialObject) {
                credentialObject.put(credentialKey, newValue);
                return true;
            }

            if (paramsObject.has(credentialKey)) {
                paramsObject.put(credentialKey, newValue);
                return true;
            }

            ObjectNode injected = paramsObject.putObject("credentials");
            injected.put(credentialKey, newValue);
            return true;
        });
    }

    public static String mutateFirstMatchingId(String rawHttpRequest, int callIndex, String newValue) {
        return mutateRequestBody(rawHttpRequest, root -> {
            ObjectNode call = resolveCallNode(root, callIndex);
            if (call == null) {
                return false;
            }

            JsonNode params = call.path("params");
            if (params.isMissingNode() || params.isNull()) {
                return false;
            }

            return mutateFirstIdLikeField(params, newValue, 0);
        });
    }

    public static String mutateFirstMatchingValueInParams(
            String rawHttpRequest,
            int callIndex,
            String expectedCurrentValue,
            String newValue
    ) {
        if (expectedCurrentValue == null || expectedCurrentValue.isBlank()) {
            return rawHttpRequest;
        }

        return mutateRequestBody(rawHttpRequest, root -> {
            ObjectNode call = resolveCallNode(root, callIndex);
            if (call == null) {
                return false;
            }

            JsonNode params = call.path("params");
            if (params.isMissingNode() || params.isNull()) {
                return false;
            }

            return mutateFirstMatchingValue(params, expectedCurrentValue, newValue, 0);
        });
    }

    public static String mutateFirstMatchingKeyValueInParams(
            String rawHttpRequest,
            int callIndex,
            String targetKey,
            String expectedCurrentValue,
            String newValue
    ) {
        if (targetKey == null || targetKey.isBlank() || expectedCurrentValue == null || expectedCurrentValue.isBlank()) {
            return rawHttpRequest;
        }

        return mutateRequestBody(rawHttpRequest, root -> {
            ObjectNode call = resolveCallNode(root, callIndex);
            if (call == null) {
                return false;
            }

            JsonNode params = call.path("params");
            if (params.isMissingNode() || params.isNull()) {
                return false;
            }

            return mutateFirstMatchingKeyValue(params, targetKey, expectedCurrentValue, newValue, 0);
        });
    }

    public static String removeRequestId(String rawHttpRequest, int callIndex) {
        return mutateRequestBody(rawHttpRequest, root -> {
            ObjectNode call = resolveCallNode(root, callIndex);
            if (call == null || !call.has("id")) {
                return false;
            }
            call.remove("id");
            return true;
        });
    }

    public static String convertNamedToPositional(String rawHttpRequest, int callIndex) {
        return mutateRequestBody(rawHttpRequest, root -> {
            ObjectNode call = resolveCallNode(root, callIndex);
            if (call == null) {
                return false;
            }
            JsonNode params = call.path("params");
            if (!(params instanceof ObjectNode paramsObject)) {
                return false;
            }

            ArrayNode positional = OBJECT_MAPPER.createArrayNode();
            Iterator<Map.Entry<String, JsonNode>> iterator = paramsObject.fields();
            while (iterator.hasNext()) {
                positional.add(iterator.next().getValue());
            }
            call.set("params", positional);
            return true;
        });
    }

    public static String convertPositionalToNamed(String rawHttpRequest, int callIndex) {
        return mutateRequestBody(rawHttpRequest, root -> {
            ObjectNode call = resolveCallNode(root, callIndex);
            if (call == null) {
                return false;
            }
            JsonNode params = call.path("params");
            if (!(params instanceof ArrayNode paramsArray)) {
                return false;
            }

            ObjectNode named = OBJECT_MAPPER.createObjectNode();
            for (int i = 0; i < paramsArray.size(); i++) {
                named.set("arg" + i, paramsArray.get(i));
            }
            call.set("params", named);
            return true;
        });
    }

    public static String removeOneNestedParam(String rawHttpRequest, int callIndex) {
        return mutateRequestBody(rawHttpRequest, root -> {
            ObjectNode call = resolveCallNode(root, callIndex);
            if (call == null) {
                return false;
            }
            JsonNode params = call.path("params");
            if (!(params instanceof ObjectNode paramsObject)) {
                return false;
            }

            Iterator<String> fields = paramsObject.fieldNames();
            if (!fields.hasNext()) {
                return false;
            }

            String first = fields.next();
            paramsObject.remove(first);
            return true;
        });
    }

    public static String addExtraParam(String rawHttpRequest, int callIndex, String key, String value) {
        return mutateRequestBody(rawHttpRequest, root -> {
            ObjectNode call = resolveCallNode(root, callIndex);
            if (call == null) {
                return false;
            }
            JsonNode params = call.path("params");
            if (!(params instanceof ObjectNode paramsObject)) {
                return false;
            }
            paramsObject.put(key, value);
            return true;
        });
    }

    public static String reorderParams(String rawHttpRequest, int callIndex) {
        return mutateRequestBody(rawHttpRequest, root -> {
            ObjectNode call = resolveCallNode(root, callIndex);
            if (call == null) {
                return false;
            }
            JsonNode params = call.path("params");
            if (!(params instanceof ObjectNode paramsObject)) {
                return false;
            }

            List<Map.Entry<String, JsonNode>> entries = new ArrayList<>();
            paramsObject.fields().forEachRemaining(entries::add);
            if (entries.size() < 2) {
                return false;
            }

            ObjectNode reordered = OBJECT_MAPPER.createObjectNode();
            for (int i = entries.size() - 1; i >= 0; i--) {
                reordered.set(entries.get(i).getKey(), entries.get(i).getValue());
            }
            call.set("params", reordered);
            return true;
        });
    }

    public static String swapDatabaseInBody(String rawHttpRequest, int callIndex, String newDatabase) {
        return mutateCredentialField(rawHttpRequest, callIndex, "database", newDatabase);
    }

    private static String mutateRequestBody(String rawHttpRequest, JsonMutation mutation) {
        if (rawHttpRequest == null || rawHttpRequest.isBlank()) {
            return "";
        }

        boolean escapedMode = rawHttpRequest.contains("\\r\\n") && !rawHttpRequest.contains("\r\n");
        String parseable = escapedMode ? rawHttpRequest.replace("\\r\\n", "\r\n") : rawHttpRequest;

        HttpParts parts = HttpParts.split(parseable);
        if (parts.body().isBlank()) {
            return rawHttpRequest;
        }

        final JsonNode root;
        try {
            root = OBJECT_MAPPER.readTree(parts.body());
        } catch (Exception ignored) {
            return rawHttpRequest;
        }

        boolean changed;
        try {
            changed = mutation.apply(root);
        } catch (Exception ignored) {
            return rawHttpRequest;
        }

        if (!changed) {
            return rawHttpRequest;
        }

        String mutatedBody;
        try {
            mutatedBody = OBJECT_MAPPER.writeValueAsString(root);
        } catch (Exception ignored) {
            return rawHttpRequest;
        }

        String merged = parts.withBody(mutatedBody).rebuildWithUpdatedContentLength(mutatedBody);
        if (escapedMode) {
            return merged.replace("\r\n", "\\r\\n");
        }
        return merged;
    }

    private static ObjectNode resolveCallNode(JsonNode root, int callIndex) {
        if (root instanceof ObjectNode objectNode) {
            return objectNode;
        }

        if (!root.isArray()) {
            return null;
        }

        if (callIndex < 0 || callIndex >= root.size()) {
            return null;
        }

        JsonNode item = root.get(callIndex);
        return item instanceof ObjectNode objectNode ? objectNode : null;
    }

    private static boolean mutateFirstIdLikeField(JsonNode node, String newValue, int depth) {
        if (node == null || depth > 8) {
            return false;
        }

        if (node.isObject()) {
            ObjectNode objectNode = (ObjectNode) node;
            Iterator<Map.Entry<String, JsonNode>> fields = objectNode.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> entry = fields.next();
                String key = entry.getKey();
                JsonNode value = entry.getValue();

                if (isIdLikeKey(key) && value != null && value.isValueNode()) {
                    objectNode.put(key, newValue);
                    return true;
                }

                if (mutateFirstIdLikeField(value, newValue, depth + 1)) {
                    return true;
                }
            }
            return false;
        }

        if (node.isArray()) {
            for (JsonNode item : node) {
                if (mutateFirstIdLikeField(item, newValue, depth + 1)) {
                    return true;
                }
            }
        }

        return false;
    }

    private static boolean mutateFirstMatchingValue(JsonNode node, String expectedCurrentValue, String newValue, int depth) {
        if (node == null || depth > 8) {
            return false;
        }

        if (node.isObject()) {
            ObjectNode objectNode = (ObjectNode) node;
            Iterator<Map.Entry<String, JsonNode>> fields = objectNode.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> entry = fields.next();
                String key = entry.getKey();
                JsonNode value = entry.getValue();

                if (isMatchingScalar(value, expectedCurrentValue)) {
                    objectNode.set(key, replacementNodeFor(value, newValue));
                    return true;
                }

                if (mutateFirstMatchingValue(value, expectedCurrentValue, newValue, depth + 1)) {
                    return true;
                }
            }
            return false;
        }

        if (node.isArray()) {
            ArrayNode arrayNode = (ArrayNode) node;
            for (int i = 0; i < arrayNode.size(); i++) {
                JsonNode value = arrayNode.get(i);
                if (isMatchingScalar(value, expectedCurrentValue)) {
                    arrayNode.set(i, replacementNodeFor(value, newValue));
                    return true;
                }

                if (mutateFirstMatchingValue(value, expectedCurrentValue, newValue, depth + 1)) {
                    return true;
                }
            }
        }

        return false;
    }

    private static boolean mutateFirstMatchingKeyValue(
            JsonNode node,
            String targetKey,
            String expectedCurrentValue,
            String newValue,
            int depth
    ) {
        if (node == null || depth > 8) {
            return false;
        }

        if (node.isObject()) {
            ObjectNode objectNode = (ObjectNode) node;
            Iterator<Map.Entry<String, JsonNode>> fields = objectNode.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> entry = fields.next();
                String key = entry.getKey();
                JsonNode value = entry.getValue();

                if (key != null
                        && key.equalsIgnoreCase(targetKey)
                        && isMatchingScalar(value, expectedCurrentValue)) {
                    objectNode.set(key, replacementNodeFor(value, newValue));
                    return true;
                }

                if (mutateFirstMatchingKeyValue(value, targetKey, expectedCurrentValue, newValue, depth + 1)) {
                    return true;
                }
            }
            return false;
        }

        if (node.isArray()) {
            ArrayNode arrayNode = (ArrayNode) node;
            for (int i = 0; i < arrayNode.size(); i++) {
                if (mutateFirstMatchingKeyValue(arrayNode.get(i), targetKey, expectedCurrentValue, newValue, depth + 1)) {
                    return true;
                }
            }
        }

        return false;
    }

    private static boolean isMatchingScalar(JsonNode node, String expectedCurrentValue) {
        if (node == null || !node.isValueNode() || node.isNull()) {
            return false;
        }
        return expectedCurrentValue.equals(node.asText(""));
    }

    private static JsonNode replacementNodeFor(JsonNode previousValue, String replacement) {
        String nextValue = replacement == null ? "" : replacement;
        if (previousValue == null || previousValue.isNull()) {
            return new TextNode(nextValue);
        }

        if (previousValue.isIntegralNumber()) {
            try {
                return OBJECT_MAPPER.getNodeFactory().numberNode(Long.parseLong(nextValue));
            } catch (NumberFormatException ignored) {
                return new TextNode(nextValue);
            }
        }

        if (previousValue.isFloatingPointNumber()) {
            try {
                return OBJECT_MAPPER.getNodeFactory().numberNode(Double.parseDouble(nextValue));
            } catch (NumberFormatException ignored) {
                return new TextNode(nextValue);
            }
        }

        if (previousValue.isBoolean()) {
            if ("true".equalsIgnoreCase(nextValue)) {
                return OBJECT_MAPPER.getNodeFactory().booleanNode(true);
            }
            if ("false".equalsIgnoreCase(nextValue)) {
                return OBJECT_MAPPER.getNodeFactory().booleanNode(false);
            }
            return new TextNode(nextValue);
        }

        return new TextNode(nextValue);
    }

    private static boolean isIdLikeKey(String key) {
        if (key == null || key.isBlank()) {
            return false;
        }
        String lowered = key.toLowerCase(Locale.ROOT);
        return lowered.equals("id")
                || lowered.endsWith("id")
                || lowered.contains("_id")
                || lowered.contains("tenant")
                || lowered.contains("database")
                || lowered.equals("db")
                || lowered.contains("session")
                || lowered.contains("user")
                || lowered.contains("group")
                || lowered.contains("device")
                || lowered.contains("report")
                || lowered.contains("schedule")
                || lowered.contains("rule");
    }

    private interface JsonMutation {
        boolean apply(JsonNode root);
    }

    private record HttpParts(String headers, String body, String separator) {
        private static HttpParts split(String rawHttp) {
            int split = rawHttp.indexOf("\r\n\r\n");
            if (split >= 0) {
                return new HttpParts(rawHttp.substring(0, split), rawHttp.substring(split + 4), "\r\n\r\n");
            }

            split = rawHttp.indexOf("\n\n");
            if (split >= 0) {
                return new HttpParts(rawHttp.substring(0, split), rawHttp.substring(split + 2), "\n\n");
            }

            return new HttpParts(rawHttp, "", "\r\n\r\n");
        }

        private HttpParts withBody(String nextBody) {
            return new HttpParts(headers, nextBody == null ? "" : nextBody, separator);
        }

        private String rebuildWithUpdatedContentLength(String nextBody) {
            String lineSeparator = "\r\n\r\n".equals(separator) ? "\r\n" : "\n";
            String[] lines = headers.split(Pattern.quote(lineSeparator), -1);

            StringBuilder rebuiltHeaders = new StringBuilder();
            int contentLength = nextBody.getBytes(StandardCharsets.UTF_8).length;
            boolean replaced = false;

            for (int i = 0; i < lines.length; i++) {
                String line = lines[i];
                if (line.toLowerCase(Locale.ROOT).startsWith("content-length:")) {
                    line = "Content-Length: " + contentLength;
                    replaced = true;
                }
                rebuiltHeaders.append(line);
                if (i < lines.length - 1) {
                    rebuiltHeaders.append(lineSeparator);
                }
            }

            if (!replaced) {
                rebuiltHeaders.append(lineSeparator).append("Content-Length: ").append(contentLength);
            }

            return rebuiltHeaders + separator + nextBody;
        }
    }
}
