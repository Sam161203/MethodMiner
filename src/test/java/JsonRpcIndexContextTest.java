import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JsonRpcIndexContextTest {
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final JsonRpcParser parser = new JsonRpcParser(objectMapper, 128);

    @Test
    void storesMethodTrafficPerContextIndependently() throws Exception {
        JsonRpcIndex index = new JsonRpcIndex();

        JsonRpcRecord admin = createRecord(
                "https://bugcrowd5.geotab.com/apiv1",
                "sid-admin",
                "db-admin",
                "admin.user",
                "d-admin-9"
        );

        JsonRpcRecord low = createRecord(
                "https://bugcrowd5.geotab.com/apiv1",
                "sid-low",
                "db-low",
                "low.user",
                "d-low-1"
        );

        JsonRpcNormalizedRecord adminNorm = parser.normalize(admin);
        JsonRpcNormalizedRecord lowNorm = parser.normalize(low);

        index.addRecord(adminNorm, admin, "host=bugcrowd5.geotab.com|db=db-admin|sid=sid-admin|user=admin.user");
        index.addRecord(lowNorm, low, "host=bugcrowd5.geotab.com|db=db-low|sid=sid-low|user=low.user");

        List<JsonRpcIndex.ContextRow> contextRows = index.snapshotContextRows();
        assertEquals(2, contextRows.size());
        assertTrue(contextRows.stream().allMatch(row -> row.count() == 1));

        JsonRpcIndex.MethodDetails details = index.snapshotMethodDetails("Device.Get").orElseThrow();
        assertEquals(2, details.contextSummaries().size());
        assertTrue(details.contextSummaries().stream().anyMatch(c -> c.contextKey().contains("sid-admin")));
        assertTrue(details.contextSummaries().stream().anyMatch(c -> c.contextKey().contains("sid-low")));
    }

    private JsonRpcRecord createRecord(
            String url,
            String sessionId,
            String database,
            String userName,
            String deviceId
    ) {
        String requestBody = "{"
                + "\"jsonrpc\":\"2.0\","
                + "\"method\":\"Device.Get\","
                + "\"params\":{"
                + "\"credentials\":{"
                + "\"database\":\"" + database + "\","
                + "\"sessionId\":\"" + sessionId + "\","
                + "\"userName\":\"" + userName + "\""
                + "},"
                + "\"search\":{\"deviceId\":\"" + deviceId + "\"}"
                + "},"
                + "\"id\":1"
                + "}";

        String rawRequest = "POST /apiv1 HTTP/1.1\r\n"
                + "Host: bugcrowd5.geotab.com\r\n"
                + "Content-Type: application/json\r\n"
                + "Cookie: sessionId=" + sessionId + "\r\n\r\n"
                + requestBody;

        JsonRpcRecord.RequestData requestData = JsonRpcRecord.RequestData.fromCaptured(
                url,
                "POST",
                List.of(
                        "Host: bugcrowd5.geotab.com",
                        "Content-Type: application/json",
                        "Cookie: sessionId=" + sessionId
                ),
                requestBody,
                requestBody.getBytes(StandardCharsets.UTF_8),
                rawRequest,
                rawRequest.getBytes(StandardCharsets.UTF_8)
        );

        String responseBody = "{\"result\":{\"deviceId\":\"" + deviceId + "\"},\"id\":1}";
        String responseRaw = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + responseBody;

        JsonRpcRecord.ResponseData responseData = JsonRpcRecord.ResponseData.fromCaptured(
                200,
                List.of("Content-Type: application/json"),
                responseBody,
                responseBody.getBytes(StandardCharsets.UTF_8),
                responseRaw,
                responseRaw.getBytes(StandardCharsets.UTF_8)
        );

        return new JsonRpcRecord(
                null,
                1,
                Instant.now(),
                "Proxy",
                requestData,
                responseData
        );
    }
}
