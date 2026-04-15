import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JsonRpcParserTest {
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final JsonRpcParser parser = new JsonRpcParser(objectMapper, 1024);

    @Test
    void probeDetectsValidJsonRpcRequest() throws Exception {
        String body = readFixture("fixtures/jsonrpc-request-basic.json");
        JsonRpcParser.ProbeResult result = parser.probeRequestBody(body);

        assertTrue(result.isCandidate());
        assertEquals(JsonRpcParser.ProbeKind.CANDIDATE, result.kind());
        assertEquals("user.getProfile", result.methodName());
    }

    @Test
    void probeFlagsMalformedJsonWithoutThrowing() {
        JsonRpcParser.ProbeResult result = parser.probeRequestBody("{\"method\":\"a\",\"params\":");

        assertFalse(result.isCandidate());
        assertTrue(result.isMalformedJson());
    }

    @Test
    void probeSkipsNonJsonBodyByPrefixCheck() {
        JsonRpcParser.ProbeResult result = parser.probeRequestBody("method=user.getProfile&params=%7B%7D");

        assertFalse(result.isCandidate());
        assertFalse(result.isMalformedJson());
        assertEquals("not-json", result.reason());
    }

    @Test
    void normalizeExtractsExpectedMetadata() throws Exception {
        String requestBody = readFixture("fixtures/jsonrpc-request-basic.json");
        String responseBody = readFixture("fixtures/jsonrpc-response-basic.json");

        JsonRpcRecord record = createRecord(requestBody, responseBody);
        JsonRpcNormalizedRecord normalized = parser.normalize(record);

        assertEquals("user.getProfile", normalized.methodName());
        assertEquals("POST", normalized.httpMethod());
        assertEquals("object", normalized.paramsKind());
        assertEquals(List.of("includeSecrets", "userId"), normalized.parameterKeys());
        assertFalse(normalized.emptyParams());
        assertEquals(200, normalized.responseStatus());
        assertTrue(normalized.variantSignature().contains("param="));
    }

    @Test
    void normalizeHandlesMissingResponseSafely() throws Exception {
        String requestBody = readFixture("fixtures/jsonrpc-request-basic.json");
        JsonRpcRecord record = createRecord(requestBody, null);

        JsonRpcNormalizedRecord normalized = parser.normalize(record);

        assertEquals("missing-response", normalized.responseShapeSignature());
        assertEquals(null, normalized.responseStatus());
    }

    @Test
    void probeDetectsBatchJsonRpcRequest() {
        String body = "[{\"jsonrpc\":\"2.0\",\"method\":\"Device.Get\",\"params\":{\"id\":\"d-1\"},\"id\":1}]";
        JsonRpcParser.ProbeResult result = parser.probeRequestBody(body);

        assertTrue(result.isCandidate());
        assertEquals("Device.Get", result.methodName());
    }

    @Test
    void normalizeCapturesBatchNotificationAndNestedMetadata() throws Exception {
        String batchBody = "[{\"jsonrpc\":\"2.0\",\"method\":\"Device.Get\",\"params\":[\"d-1\",\"d-2\"],\"id\":11},"
                + "{\"jsonrpc\":\"2.0\",\"method\":\"Device.Get\",\"params\":{\"id\":\"d-3\"}}]";

        JsonRpcRecord batchRecord = createRecord(batchBody, "{\"result\":[],\"id\":11}");
        JsonRpcNormalizedRecord batchNormalized = parser.normalize(batchRecord);

        assertTrue(batchNormalized.batchRequest());
        assertEquals("positional", batchNormalized.paramsMode());
        assertEquals(List.of("arg[0]", "arg[1]"), batchNormalized.parameterKeys());
        assertEquals("2.0", batchNormalized.rpcVersion());

        String nestedBody = "{\"jsonrpc\":\"2.0\",\"method\":\"ExecuteMultiCall\","
                + "\"params\":{\"typeName\":\"Device\",\"calls\":["
                + "{\"method\":\"Device.Get\",\"params\":{\"search\":{\"deviceId\":\"d-1\"}}},"
                + "{\"method\":\"Device.Set\",\"params\":{\"entity\":{\"deviceId\":\"d-1\"}}}]}}";

        JsonRpcRecord nestedRecord = createRecord(nestedBody, "{\"result\":[],\"id\":null}");
        JsonRpcNormalizedRecord nestedNormalized = parser.normalize(nestedRecord);

        assertEquals("ExecuteMultiCall", nestedNormalized.methodName());
        assertEquals("Device", nestedNormalized.typeName());
        assertTrue(nestedNormalized.notificationRequest());
        assertTrue(nestedNormalized.nestedMethods().contains("Device.Get"));
        assertTrue(nestedNormalized.nestedMethods().contains("Device.Set"));

        List<JsonRpcNormalizedRecord> expanded = parser.normalizeAll(nestedRecord);
        Set<String> methods = new HashSet<>();
        for (JsonRpcNormalizedRecord item : expanded) {
            methods.add(item.methodName());
        }

        assertTrue(methods.contains("ExecuteMultiCall"));
        assertTrue(methods.contains("Device.Get"));
        assertTrue(methods.contains("Device.Set"));
    }

    private JsonRpcRecord createRecord(String requestBody, String responseBody) {
        String rawRequest = "POST /rpc HTTP/1.1\r\nHost: example.test\r\nContent-Type: text/plain\r\n\r\n" + requestBody;
        JsonRpcRecord.RequestData request = JsonRpcRecord.RequestData.fromCaptured(
                "https://example.test/rpc",
                "POST",
                List.of("Host: example.test", "Content-Type: text/plain"),
                requestBody,
                requestBody.getBytes(StandardCharsets.UTF_8),
                rawRequest,
                rawRequest.getBytes(StandardCharsets.UTF_8)
        );

        JsonRpcRecord.ResponseData response = responseBody == null
                ? JsonRpcRecord.ResponseData.missing()
                : JsonRpcRecord.ResponseData.fromCaptured(
                200,
                List.of("Content-Type: application/json"),
                responseBody,
                responseBody.getBytes(StandardCharsets.UTF_8),
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + responseBody,
                ("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + responseBody).getBytes(StandardCharsets.UTF_8)
        );

        return new JsonRpcRecord(
                "rec-1",
                1,
                Instant.parse("2026-04-09T00:00:00Z"),
                "Proxy",
                request,
                response
        );
    }

    private String readFixture(String resourcePath) throws IOException {
        try (var stream = getClass().getClassLoader().getResourceAsStream(resourcePath)) {
            if (stream == null) {
                throw new IOException("Missing fixture: " + resourcePath);
            }
            return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
