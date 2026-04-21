import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RepeaterRequestMutatorTest {
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void mutateFirstMatchingKeyValueOnlyPatchesTargetField() throws Exception {
        String raw = buildRawRequest(
                "{\"jsonrpc\":\"2.0\",\"method\":\"Device.Set\",\"params\":{\"credentials\":{\"database\":\"db-low\",\"sessionId\":\"sid-low\",\"userName\":\"low.user\"},\"entity\":{\"deviceId\":\"d-low-1\",\"groupId\":\"g-low\"}},\"id\":1}"
        );

        String mutated = RepeaterRequestMutator.mutateFirstMatchingKeyValueInParams(
                raw,
                0,
                "groupId",
                "g-low",
                "g-admin"
        );

        assertNotEquals(raw, mutated);

        JsonNode body = parseBody(mutated);
        assertEquals("Device.Set", body.path("method").asText());
        assertEquals("d-low-1", body.path("params").path("entity").path("deviceId").asText());
        assertEquals("g-admin", body.path("params").path("entity").path("groupId").asText());

        assertContentLengthMatchesBody(mutated);
    }

    @Test
    void mutateFirstMatchingValueInParamsKeepsHttpEnvelopeValid() throws Exception {
        String raw = buildRawRequest(
                "{\"jsonrpc\":\"2.0\",\"method\":\"Device.Get\",\"params\":{\"search\":{\"deviceId\":\"d-low-1\"},\"credentials\":{\"database\":\"db-low\"}},\"id\":1}"
        );

        String mutated = RepeaterRequestMutator.mutateFirstMatchingValueInParams(
                raw,
                0,
                "d-low-1",
                "d-admin-9"
        );

        assertNotEquals(raw, mutated);

        JsonNode body = parseBody(mutated);
        assertEquals("d-admin-9", body.path("params").path("search").path("deviceId").asText());
        assertEquals("db-low", body.path("params").path("credentials").path("database").asText());

        assertContentLengthMatchesBody(mutated);
    }

    private String buildRawRequest(String body) {
        List<String> headers = List.of(
                "Host: tenant-a.example.test",
                "Content-Type: application/json",
                "Cookie: sessionId=sid-low",
                "Authorization: Bearer token-low",
                "Content-Length: " + body.getBytes(StandardCharsets.UTF_8).length
        );

        return "POST /apiv1 HTTP/1.1\r\n"
                + String.join("\r\n", headers)
                + "\r\n\r\n"
                + body;
    }

    private JsonNode parseBody(String rawHttp) throws Exception {
        int split = rawHttp.indexOf("\r\n\r\n");
        String body = split >= 0 ? rawHttp.substring(split + 4) : "";
        return objectMapper.readTree(body);
    }

    private void assertContentLengthMatchesBody(String rawHttp) {
        int split = rawHttp.indexOf("\r\n\r\n");
        String head = split >= 0 ? rawHttp.substring(0, split) : rawHttp;
        String body = split >= 0 ? rawHttp.substring(split + 4) : "";

        int contentLength = -1;
        for (String line : head.split("\\r?\\n")) {
            if (line.toLowerCase().startsWith("content-length:")) {
                contentLength = Integer.parseInt(line.substring(line.indexOf(':') + 1).trim());
                break;
            }
        }

        assertTrue(contentLength >= 0, "Content-Length header must exist");
        assertEquals(body.getBytes(StandardCharsets.UTF_8).length, contentLength);
    }
}
