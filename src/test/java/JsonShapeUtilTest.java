import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JsonShapeUtilTest {
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void shapeSignatureDifferentiatesByKeyAndType() throws Exception {
        JsonNode first = objectMapper.readTree("{\"a\":1,\"b\":true}");
        JsonNode second = objectMapper.readTree("{\"a\":\"1\",\"b\":true}");

        String firstShape = JsonShapeUtil.shapeSignature(first);
        String secondShape = JsonShapeUtil.shapeSignature(second);

        assertEquals("obj{a:integer,b:boolean}", firstShape);
        assertEquals("obj{a:string,b:boolean}", secondShape);
    }

    @Test
    void arrayShapeCapturesLengthAndElementTypes() throws Exception {
        JsonNode node = objectMapper.readTree("[1,2,{\"x\":1},\"s\"]");
        String shape = JsonShapeUtil.shapeSignature(node);

        assertTrue(shape.contains("len=4"));
        assertTrue(shape.contains("integer"));
        assertTrue(shape.contains("obj{x:integer}"));
        assertTrue(shape.contains("string"));
    }

    @Test
    void emptyParamDetectionHandlesCommonCases() throws Exception {
        JsonNode emptyObject = objectMapper.readTree("{}");
        JsonNode emptyArray = objectMapper.readTree("[]");
        JsonNode nonEmptyObject = objectMapper.readTree("{\"x\":1}");

        assertTrue(JsonShapeUtil.isEmptyParams(null));
        assertTrue(JsonShapeUtil.isEmptyParams(objectMapper.nullNode()));
        assertTrue(JsonShapeUtil.isEmptyParams(emptyObject));
        assertTrue(JsonShapeUtil.isEmptyParams(emptyArray));
        assertFalse(JsonShapeUtil.isEmptyParams(nonEmptyObject));
    }
}
