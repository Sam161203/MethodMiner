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
    void tracksEntityReuseAcrossMethodsAndContexts() throws Exception {
        try (EntityStoreService entityStoreService = new EntityStoreService(objectMapper, new NoopLogging())) {
            JsonRpcRecord first = createRecord(
                    "user.lookup",
                    List.of("Host: example.test", "Cookie: sessionId=user-a"),
                    "{\"params\":{\"email\":\"alice@example.test\"}}",
                    200,
                    "{\"result\":{\"userId\":\"u-100\",\"tenantId\":\"t-1\"},\"id\":1}"
            );

            JsonRpcRecord second = createRecord(
                    "report.fetch",
                    List.of("Host: example.test", "Cookie: sessionId=user-a"),
                    "{\"params\":{\"userId\":\"u-100\"}}",
                    200,
                    "{\"result\":{\"reportId\":\"r-7\",\"tenantId\":\"t-1\"},\"id\":1}"
            );

            JsonRpcRecord third = createRecord(
                    "report.fetch",
                    List.of("Host: example.test", "Cookie: sessionId=user-b"),
                    "{\"params\":{\"userId\":\"u-100\"}}",
                    403,
                    "{\"error\":{\"code\":403,\"message\":\"forbidden\"},\"id\":1}"
            );

            entityStoreService.ingestRecordSync(first, parser.normalize(first));
            entityStoreService.ingestRecordSync(second, parser.normalize(second));
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

    private EntityStoreService.EntityRow findEntity(List<EntityStoreService.EntityRow> rows, String preview) {
        for (EntityStoreService.EntityRow row : rows) {
            if (preview.equals(row.preview())) {
                return row;
            }
        }
        return null;
    }

    private JsonRpcRecord createRecord(
            String method,
            List<String> headers,
            String paramsSuffix,
            Integer responseStatus,
            String responseBody
    ) {
        String requestBody = "{\"jsonrpc\":\"2.0\",\"method\":\"" + method + "\"," + paramsSuffix.substring(1);

        String rawRequest = "POST /rpc HTTP/1.1\\r\\n"
                + String.join("\\r\\n", headers)
                + "\\r\\nContent-Type: application/json\\r\\n\\r\\n"
                + requestBody;

        JsonRpcRecord.RequestData requestData = JsonRpcRecord.RequestData.fromCaptured(
                "https://example.test/rpc",
                "POST",
                headers,
                requestBody,
                requestBody.getBytes(StandardCharsets.UTF_8),
                rawRequest,
                rawRequest.getBytes(StandardCharsets.UTF_8)
        );

        String responseRaw = "HTTP/1.1 " + responseStatus + "\\r\\n"
                + "Content-Type: application/json\\r\\n\\r\\n"
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
                null,
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
