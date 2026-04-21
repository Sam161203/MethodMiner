import burp.api.montoya.logging.Logging;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EntityStoreServiceTest {
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final JsonRpcParser parser = new JsonRpcParser(objectMapper, 1024);

    @Test
    void tracksEntityReuseAcrossMethodsAndSessions() throws Exception {
        AuthContextStore authContextStore = new AuthContextStore(objectMapper);
        try (EntityStoreService entityStoreService = new EntityStoreService(objectMapper, new NoopLogging(), authContextStore)) {
            JsonRpcRecord first = createRecord(
                    "rec-1",
                    "Device.Get",
                    "Device",
                    "sid-a",
                    "db-a",
                    "alice",
                    "u-100",
                    200,
                    "{\"result\":[{\"id\":\"u-100\",\"typeName\":\"User\"}],\"id\":1}"
            );

            JsonRpcRecord second = createRecord(
                    "rec-2",
                    "User.Get",
                    "User",
                    "sid-a",
                    "db-a",
                    "alice",
                    "u-100",
                    200,
                    "{\"result\":[{\"id\":\"u-100\",\"typeName\":\"User\"}],\"id\":2}"
            );

            JsonRpcRecord third = createRecord(
                    "rec-3",
                    "User.Get",
                    "User",
                    "sid-b",
                    "db-b",
                    "bob",
                    "u-100",
                    200,
                    "{\"result\":[{\"id\":\"u-100\",\"typeName\":\"User\"}],\"id\":3}"
            );

            // Prime AuthContextStore first — EntityStoreService now uses non-mutating lookupContext
            authContextStore.observeRecord(first, "Device.Get");
            entityStoreService.ingestRecordSync(first, parser.normalize(first));
            authContextStore.observeRecord(second, "User.Get");
            entityStoreService.ingestRecordSync(second, parser.normalize(second));
            authContextStore.observeRecord(third, "User.Get");
            entityStoreService.ingestRecordSync(third, parser.normalize(third));

            List<EntityStoreService.EntityRow> rows = entityStoreService.snapshotRows();
            assertFalse(rows.isEmpty());

            EntityStoreService.EntityRow userEntity = findEntity(rows, "u-100");
            assertNotNull(userEntity);
            assertTrue(userEntity.crossMethodReuse());
            assertTrue(userEntity.crossContextReuse());

            EntityStoreService.EntityDetails details = entityStoreService.snapshotEntityDetails(userEntity.entityKey()).orElse(null);
            assertNotNull(details);
            assertTrue(details.methods().size() >= 2);
            assertTrue(details.authContexts().size() >= 2);
        }
    }

    private EntityStoreService.EntityRow findEntity(List<EntityStoreService.EntityRow> rows, String entityId) {
        for (EntityStoreService.EntityRow row : rows) {
            if (entityId.equals(row.entityKey())) {
                return row;
            }
        }
        return null;
    }

    private JsonRpcRecord createRecord(
            String recordId,
            String method,
            String typeName,
            String sessionId,
            String database,
            String userName,
            String entityId,
            Integer responseStatus,
            String responseBody
    ) {
        String requestBody = "{"
                + "\"jsonrpc\":\"2.0\"," 
                + "\"method\":\"" + method + "\"," 
                + "\"params\":{"
                + "\"typeName\":\"" + typeName + "\"," 
                + "\"search\":{\"id\":\"" + entityId + "\"},"
                + "\"credentials\":{"
                + "\"database\":\"" + database + "\"," 
                + "\"sessionId\":\"" + sessionId + "\"," 
                + "\"userName\":\"" + userName + "\""
                + "}"
                + "},"
                + "\"id\":1"
                + "}";

        List<String> headers = List.of(
                "Host: api.example.test",
                "Content-Type: application/json"
        );

        String rawRequest = "POST /apiv1 HTTP/1.1\r\n"
                + String.join("\r\n", headers)
                + "\r\n\r\n"
                + requestBody;

        JsonRpcRecord.RequestData requestData = JsonRpcRecord.RequestData.fromCaptured(
                "https://api.example.test/apiv1",
                "POST",
                headers,
                requestBody,
                requestBody.getBytes(StandardCharsets.UTF_8),
                rawRequest,
                rawRequest.getBytes(StandardCharsets.UTF_8)
        );

        String responseRaw = "HTTP/1.1 " + responseStatus + "\r\n"
                + "Content-Type: application/json\r\n\r\n"
                + responseBody;

        JsonRpcRecord.ResponseData responseData = JsonRpcRecord.ResponseData.fromCaptured(
                responseStatus,
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

    private static final class NoopLogging implements Logging {
        @Override
        public java.io.PrintStream output() {
            return System.out;
        }

        @Override
        public java.io.PrintStream error() {
            return System.err;
        }

        @Override
        public void logToOutput(String message) {
        }

        @Override
        public void logToOutput(Object object) {
        }

        @Override
        public void logToError(String message) {
        }

        @Override
        public void logToError(String message, Throwable cause) {
        }

        @Override
        public void logToError(Throwable cause) {
        }

        @Override
        public void raiseDebugEvent(String message) {
        }

        @Override
        public void raiseInfoEvent(String message) {
        }

        @Override
        public void raiseErrorEvent(String message) {
        }

        @Override
        public void raiseCriticalEvent(String message) {
        }
    }
}
