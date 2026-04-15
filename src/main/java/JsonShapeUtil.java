import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.MissingNode;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

public final class JsonShapeUtil {
    private JsonShapeUtil() {
    }

    public static String shapeSignature(JsonNode node) {
        if (node == null || node instanceof MissingNode) {
            return "missing";
        }

        if (node.isNull()) {
            return "null";
        }
        if (node.isObject()) {
            List<String> segments = new ArrayList<>();
            List<String> keys = objectKeys(node);
            for (String key : keys) {
                segments.add(key + ":" + shapeSignature(node.get(key)));
            }
            return "obj{" + String.join(",", segments) + "}";
        }
        if (node.isArray()) {
            return arrayShape((ArrayNode) node);
        }
        if (node.isTextual()) {
            return "string";
        }
        if (node.isBoolean()) {
            return "boolean";
        }
        if (node.isIntegralNumber()) {
            return "integer";
        }
        if (node.isFloatingPointNumber()) {
            return "number";
        }
        if (node.isBinary()) {
            return "binary";
        }
        return node.getNodeType().name().toLowerCase();
    }

    public static String topLevelType(JsonNode node) {
        if (node == null || node instanceof MissingNode) {
            return "missing";
        }
        if (node.isNull()) {
            return "null";
        }
        if (node.isObject()) {
            return "object";
        }
        if (node.isArray()) {
            return "array";
        }
        if (node.isTextual()) {
            return "string";
        }
        if (node.isBoolean()) {
            return "boolean";
        }
        if (node.isNumber()) {
            return "number";
        }
        return node.getNodeType().name().toLowerCase();
    }

    public static List<String> objectKeys(JsonNode objectNode) {
        if (objectNode == null || !objectNode.isObject()) {
            return List.of();
        }
        Set<String> sorted = new TreeSet<>();
        Iterator<String> names = objectNode.fieldNames();
        while (names.hasNext()) {
            sorted.add(names.next());
        }
        return List.copyOf(sorted);
    }

    public static List<String> parameterKeys(JsonNode paramsNode) {
        if (paramsNode == null || !paramsNode.isObject()) {
            return List.of();
        }
        return objectKeys(paramsNode);
    }

    public static boolean isEmptyParams(JsonNode paramsNode) {
        if (paramsNode == null || paramsNode instanceof MissingNode || paramsNode.isNull()) {
            return true;
        }
        if (paramsNode.isObject()) {
            return paramsNode.isEmpty();
        }
        if (paramsNode.isArray()) {
            return paramsNode.isEmpty();
        }
        return false;
    }

    private static String arrayShape(ArrayNode arrayNode) {
        if (arrayNode == null || arrayNode.isEmpty()) {
            return "arr[len=0;items=[]]";
        }

        Set<String> itemShapes = new TreeSet<>();
        for (JsonNode item : arrayNode) {
            itemShapes.add(shapeSignature(item));
        }
        return "arr[len=" + arrayNode.size() + ";items=[" + String.join("|", itemShapes) + "]]";
    }
}
