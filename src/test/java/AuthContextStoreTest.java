import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthContextStoreTest {
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
        void sharedSessionIdAcrossHostsCreatesDistinctContexts() {
        AuthContextStore store = new AuthContextStore(objectMapper);

        JsonRpcRecord recordA = createRecord(
                "rec-a",
                "tenant-a.example.test",
                "/apiv1",
                "sid-shared",
                "db-shared",
                "alice",
                "Bearer token-a"
        );

        JsonRpcRecord recordB = createRecord(
                "rec-b",
                "tenant-b.example.test",
                "/apiv1",
                "sid-shared",
                "db-shared",
                "alice",
                "Bearer token-a"
        );

        AuthContextStore.AuthContext ctxA = store.observeRecord(recordA, "Device.Get");
        AuthContextStore.AuthContext ctxB = store.observeRecord(recordB, "Device.Get");

        assertEquals("host=tenant-a.example.test|db=db-shared|sid=sid-shared|user=alice", ctxA.contextKey());
        assertEquals("host=tenant-b.example.test|db=db-shared|sid=sid-shared|user=alice", ctxB.contextKey());
        assertNotEquals(ctxA.contextKey(), ctxB.contextKey());
        assertEquals(2, store.snapshotContexts().size());
        assertEquals(2, store.contextKeysForMethod("Device.Get").size());
    }

    @Test
        void missingSessionIdDoesNotCreateTrackedContext() {
        AuthContextStore store = new AuthContextStore(objectMapper);

        JsonRpcRecord recordA = createRecord(
                "rec-no-session-a",
                "tenant-a.example.test",
                "/apiv1",
                "",
                "db-shared",
                "alice",
                "Bearer token-a"
        );

        JsonRpcRecord recordB = createRecord(
                "rec-no-session-b",
                "tenant-a.example.test",
                "/apiv1",
                "",
                "db-shared",
                "alice",
                "Bearer token-b"
        );

        AuthContextStore.AuthContext ctxA = store.observeRecord(recordA, "Device.Get");
        AuthContextStore.AuthContext ctxB = store.observeRecord(recordB, "Device.Get");

        assertEquals("unknown-session", ctxA.contextKey());
        assertEquals("unknown-session", ctxB.contextKey());
        assertTrue(store.snapshotContexts().isEmpty());
    }

        @Test
        void roleAssignmentStaysStableAcrossCompatibleTraffic() {
                AuthContextStore store = new AuthContextStore(objectMapper);

                JsonRpcRecord first = createRecord(
                                "rec-stable-1",
                                "tenant-a.example.test",
                                "/apiv1",
                                "sid-stable",
                                "db-a",
                                "alice",
                                "Bearer token-a"
                );

                AuthContextStore.AuthContext initial = store.observeRecord(first, "Device.Get");
                assertTrue(store.setRoleForContextKey(initial.contextKey(), RoleType.ADMIN));

                JsonRpcRecord second = createRecord(
                                "rec-stable-2",
                                "tenant-a.example.test",
                                "/apiv1",
                                "sid-stable",
                                "db-a",
                                "",
                                "Bearer token-a"
                );

                AuthContextStore.AuthContext after = store.observeRecord(second, "Device.Get");
                assertEquals(initial.contextKey(), after.contextKey());
                assertEquals(RoleType.ADMIN, store.roleForContextKey(after.contextKey()));
                assertEquals(1, store.snapshotSessions().size());
        }

        @Test
        void roleCanBeSwitchedDirectly() {
                AuthContextStore store = new AuthContextStore(objectMapper);

                JsonRpcRecord record = createRecord(
                                "rec-lock-1",
                                "tenant-a.example.test",
                                "/apiv1",
                                "sid-lock",
                                "db-a",
                                "alice",
                                "Bearer token-a"
                );

                AuthContextStore.AuthContext context = store.observeRecord(record, "Device.Get");
                assertTrue(store.setRoleForContextKey(context.contextKey(), RoleType.ADMIN));

                // Role switching is now allowed — users must be able to correct mistaken tags
                boolean directSwitch = store.setRoleForContextKey(context.contextKey(), RoleType.LOW_PRIV);
                assertTrue(directSwitch);
                assertEquals(RoleType.LOW_PRIV, store.roleForContextKey(context.contextKey()));

                // And back to ADMIN
                assertTrue(store.setRoleForContextKey(context.contextKey(), RoleType.ADMIN));
                assertEquals(RoleType.ADMIN, store.roleForContextKey(context.contextKey()));
        }

            @Test
            void roleForMethodReturnsMixedWhenAdminAndLowPrivExist() {
                AuthContextStore store = new AuthContextStore(objectMapper);

                JsonRpcRecord adminRecord = createRecord(
                        "rec-mixed-admin",
                        "tenant-a.example.test",
                        "/apiv1",
                        "sid-mixed-admin",
                        "db-a",
                        "alice",
                        "Bearer token-a"
                );
                JsonRpcRecord lowPrivRecord = createRecord(
                        "rec-mixed-low",
                        "tenant-a.example.test",
                        "/apiv1",
                        "sid-mixed-low",
                        "db-a",
                        "bob",
                        "Bearer token-b"
                );

                AuthContextStore.AuthContext adminCtx = store.observeRecord(adminRecord, "Device.Get");
                AuthContextStore.AuthContext lowCtx = store.observeRecord(lowPrivRecord, "Device.Get");

                assertTrue(store.setRoleForContextKey(adminCtx.contextKey(), RoleType.ADMIN));
                assertTrue(store.setRoleForContextKey(lowCtx.contextKey(), RoleType.LOW_PRIV));

                assertEquals(RoleType.MIXED, store.roleForMethod("Device.Get"));
            }

            @Test
            void partialContextDoesNotMergeWhenAmbiguous() {
                AuthContextStore store = new AuthContextStore(objectMapper);

                JsonRpcRecord knownAlice = createRecord(
                        "rec-amb-1",
                        "tenant-a.example.test",
                        "/apiv1",
                        "sid-amb",
                        "db-a",
                        "alice",
                        "Bearer token-a"
                );
                JsonRpcRecord knownBob = createRecord(
                        "rec-amb-2",
                        "tenant-a.example.test",
                        "/apiv1",
                        "sid-amb",
                        "db-a",
                        "bob",
                        "Bearer token-b"
                );

                store.observeRecord(knownAlice, "Device.Get");
                store.observeRecord(knownBob, "Device.Get");

                JsonRpcRecord partial = createRecord(
                        "rec-amb-3",
                        "tenant-a.example.test",
                        "/apiv1",
                        "sid-amb",
                        "db-a",
                        "",
                        "Bearer token-c"
                );

                AuthContextStore.AuthContext partialCtx = store.observeRecord(partial, "Device.Get");
                assertEquals("host=tenant-a.example.test|db=db-a|sid=sid-amb|user=unknown-user", partialCtx.contextKey());
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
