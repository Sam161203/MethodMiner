import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthContextStoreTest {
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void contextKeySeparatesDifferentHostsEvenWithSharedSession() {
        AuthContextStore store = new AuthContextStore(objectMapper);

        JsonRpcRecord recordA = createRecord(
                "rec-a",
                "bugcrowd5.geotab.com",
                "/apiv1",
                "sid-shared",
                "db-shared",
                "alice",
                "Bearer token-a"
        );

        JsonRpcRecord recordB = createRecord(
                "rec-b",
                "bugcrowd6.geotab.com",
                "/apiv1",
                "sid-shared",
                "db-shared",
                "alice",
                "Bearer token-a"
        );

        AuthContextStore.AuthContext ctxA = store.observeRecord(recordA, "Device.Get");
        AuthContextStore.AuthContext ctxB = store.observeRecord(recordB, "Device.Get");

        assertNotEquals(ctxA.contextKey(), ctxB.contextKey());
        assertTrue(ctxA.contextKey().contains("host=bugcrowd5.geotab.com"));
        assertTrue(ctxB.contextKey().contains("host=bugcrowd6.geotab.com"));
        assertEquals(2, store.snapshotContexts().size());
        assertEquals(2, store.contextKeysForMethod("Device.Get").size());
    }

    @Test
    void sameHostDbUserMergesIntoSingleContextEvenWithDifferentAuthTokens() {
        AuthContextStore store = new AuthContextStore(objectMapper);

        JsonRpcRecord recordA = createRecord(
                "rec-no-session-a",
                "bugcrowd5.geotab.com",
                "/apiv1",
                "",
                "db-shared",
                "alice",
                "Bearer token-a"
        );

        JsonRpcRecord recordB = createRecord(
                "rec-no-session-b",
                "bugcrowd5.geotab.com",
                "/apiv1",
                "",
                "db-shared",
                "alice",
                "Bearer token-b"
        );

        AuthContextStore.AuthContext ctxA = store.observeRecord(recordA, "Device.Get");
        AuthContextStore.AuthContext ctxB = store.observeRecord(recordB, "Device.Get");

        // Same host + database + userName → same context key (no fragmentation)
        assertEquals(ctxA.contextKey(), ctxB.contextKey());
        // The context should store the latest auth header
        assertEquals("Bearer token-b", ctxB.rawAuthorizationHeader());
        // Only 1 context should exist (not fragmented)
        assertEquals(1, store.snapshotContexts().size());
    }

    private JsonRpcRecord createRecord(
            String recordId,
            String host,
            String path,
            String sessionId,
            String database,
            String userName,
            String authorization
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
                + "\"search\":{\"deviceId\":\"d-1\"}"
                + "},"
                + "\"id\":1"
                + "}";

        List<String> headers = new ArrayList<>();
        headers.add("Host: " + host);
        headers.add("Content-Type: application/json");
        if (authorization != null && !authorization.isBlank()) {
            headers.add("Authorization: " + authorization);
        }
        if (sessionId != null && !sessionId.isBlank()) {
            headers.add("Cookie: sessionId=" + sessionId);
        }

        String rawRequest = "POST " + path + " HTTP/1.1\r\n"
                + String.join("\r\n", headers)
                + "\r\n\r\n"
                + requestBody;

        JsonRpcRecord.RequestData requestData = JsonRpcRecord.RequestData.fromCaptured(
                "https://" + host + path,
                "POST",
                headers,
                requestBody,
                requestBody.getBytes(StandardCharsets.UTF_8),
                rawRequest,
                rawRequest.getBytes(StandardCharsets.UTF_8)
        );

        String responseBody = "{\"result\":{\"ok\":true},\"id\":1}";
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
                recordId,
                1,
                Instant.now(),
                "Proxy",
                requestData,
                responseData
        );
    }
}
