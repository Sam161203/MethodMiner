import burp.api.montoya.logging.Logging;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AttackSuggestionServiceTest {
        private static final String ALLOWED_HOSTS_PROPERTY = "logichunter.allowedHosts";

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final JsonRpcParser parser = new JsonRpcParser(objectMapper, 512);

    @Test
    void generatesFindingsForCoreDetectors() throws Exception {
        JsonRpcIndex index = new JsonRpcIndex();
        NoopLogging logging = new NoopLogging();
        AuthContextStore authContextStore = new AuthContextStore(objectMapper);

        try (SecurityAnalyzerService security = new SecurityAnalyzerService(objectMapper, index, authContextStore, logging);
             WorkflowGraphService workflow = new WorkflowGraphService(objectMapper, logging);
             EntityStoreService entityStore = new EntityStoreService(objectMapper, logging, authContextStore);
             AttackSuggestionService suggestions = new AttackSuggestionService(
                     objectMapper,
                     index,
                     security,
                     workflow,
                     entityStore,
                     authContextStore,
                     logging
             )) {

            JsonRpcRecord adminGet = createStandardRecord(
                    "admin-get",
                    "api.example.test",
                    "Device.Get",
                    "Device",
                    "sid-admin",
                    "db-admin",
                    "admin.user",
                    "x-1",
                    200,
                    "{\"result\":[{\"id\":\"x-1\",\"typeName\":\"Device\"}],\"id\":1}"
            );

            JsonRpcRecord lowGet = createStandardRecord(
                    "low-get",
                    "api.example.test",
                    "Device.Get",
                    "Device",
                    "sid-low",
                    "db-low",
                    "low.user",
                    "x-1",
                    403,
                    "{\"error\":{\"code\":403,\"message\":\"forbidden\"},\"id\":2}"
            );

            JsonRpcRecord lowMultiCall = createRawRecord(
                    "low-multicall",
                    "api.example.test",
                    "{\"jsonrpc\":\"2.0\",\"method\":\"ExecuteMultiCall\",\"params\":{\"credentials\":{\"database\":\"db-low\",\"sessionId\":\"sid-low\",\"userName\":\"low.user\"},\"calls\":[{\"method\":\"Device.Get\",\"params\":{\"typeName\":\"Device\",\"search\":{}}}]},\"id\":3}",
                    200,
                    "{\"result\":[],\"id\":3}"
            );

            ingest(index, security, workflow, entityStore, suggestions, authContextStore, adminGet);
            ingest(index, security, workflow, entityStore, suggestions, authContextStore, lowGet);
            ingest(index, security, workflow, entityStore, suggestions, authContextStore, lowMultiCall);

            authContextStore.setRoleForRecord(adminGet.recordId(), RoleType.ADMIN);
            authContextStore.setRoleForRecord(lowGet.recordId(), RoleType.LOW_PRIV);
            authContextStore.setRoleForRecord(lowMultiCall.recordId(), RoleType.LOW_PRIV);

            suggestions.recomputeSync();
            List<AttackSuggestion> rows = suggestions.snapshotSuggestions();
            assertFalse(rows.isEmpty(), "Expected findings from detector pipeline");

            Set<String> types = rows.stream().map(AttackSuggestion::findingType).collect(Collectors.toSet());
            assertTrue(types.contains("BOLA_IDOR"));
            assertTrue(types.contains("PRIVILEGE_DIFF"));
                        assertTrue(types.contains("MULTICALL_CHAIN"));
            assertTrue(types.contains("CROSS_TENANT"));
        }
    }

    @Test
    void payloadUsesBodyCredentialsAndNoAuthHeaders() throws Exception {
        JsonRpcIndex index = new JsonRpcIndex();
        NoopLogging logging = new NoopLogging();
        AuthContextStore authContextStore = new AuthContextStore(objectMapper);

        try (SecurityAnalyzerService security = new SecurityAnalyzerService(objectMapper, index, authContextStore, logging);
             WorkflowGraphService workflow = new WorkflowGraphService(objectMapper, logging);
             EntityStoreService entityStore = new EntityStoreService(objectMapper, logging, authContextStore);
             AttackSuggestionService suggestions = new AttackSuggestionService(
                     objectMapper,
                     index,
                     security,
                     workflow,
                     entityStore,
                     authContextStore,
                     logging
             )) {

            JsonRpcRecord adminGet = createStandardRecord(
                    "admin-get",
                    "api.example.test",
                    "Device.Get",
                    "Device",
                    "sid-admin",
                    "db-admin",
                    "admin.user",
                    "x-1",
                    200,
                    "{\"result\":[{\"id\":\"x-1\",\"typeName\":\"Device\"}],\"id\":1}"
            );

            JsonRpcRecord lowGet = createStandardRecord(
                    "low-get",
                    "api.example.test",
                    "Device.Get",
                    "Device",
                    "sid-low",
                    "db-low",
                    "low.user",
                    "x-1",
                    403,
                    "{\"error\":{\"code\":403,\"message\":\"forbidden\"},\"id\":2}"
            );

            ingest(index, security, workflow, entityStore, suggestions, authContextStore, adminGet);
            ingest(index, security, workflow, entityStore, suggestions, authContextStore, lowGet);

            authContextStore.setRoleForRecord(adminGet.recordId(), RoleType.ADMIN);
            authContextStore.setRoleForRecord(lowGet.recordId(), RoleType.LOW_PRIV);

            suggestions.recomputeSync();
            List<AttackSuggestion> rows = suggestions.snapshotSuggestions();
            assertFalse(rows.isEmpty());

            AttackSuggestion finding = rows.get(0);
            assertTrue(finding.payload().contains("\"credentials\""));
            assertTrue(finding.payload().contains("\"sessionId\""));
            assertFalse(finding.payload().contains("Authorization:"));
            assertFalse(finding.payload().contains("Cookie:"));
            assertTrue(finding.repeaterRequest().startsWith("POST /apiv1"));

            ObjectNode export = suggestions.buildManualExportBundle(finding.suggestionId());
            assertNotNull(export.path("curlCommand").asText(null));
            assertTrue(export.path("bugcrowdMarkdown").asText("").contains("## Summary"));
            assertTrue(export.path("bugcrowdMarkdown").asText("").contains("## Steps to Reproduce"));
        }
    }

    @Test
    void outOfScopeHostsProduceNoSuggestions() throws Exception {
        String previous = System.getProperty(ALLOWED_HOSTS_PROPERTY);
        System.setProperty(ALLOWED_HOSTS_PROPERTY, "allowed.example.com");

        JsonRpcIndex index = new JsonRpcIndex();
        NoopLogging logging = new NoopLogging();
        AuthContextStore authContextStore = new AuthContextStore(objectMapper);

        try {
            try (SecurityAnalyzerService security = new SecurityAnalyzerService(objectMapper, index, authContextStore, logging);
                 WorkflowGraphService workflow = new WorkflowGraphService(objectMapper, logging);
                 EntityStoreService entityStore = new EntityStoreService(objectMapper, logging, authContextStore);
                 AttackSuggestionService suggestions = new AttackSuggestionService(
                         objectMapper,
                         index,
                         security,
                         workflow,
                         entityStore,
                         authContextStore,
                         logging
                 )) {

                JsonRpcRecord recordA = createStandardRecord(
                        "out-a",
                        "example.com",
                        "Device.Get",
                        "Device",
                        "sid-a",
                        "db-a",
                        "user-a",
                        "d-a",
                        200,
                        "{\"result\":[{\"id\":\"d-a\",\"typeName\":\"Device\"}],\"id\":1}"
                );

                JsonRpcRecord recordB = createStandardRecord(
                        "out-b",
                        "api.example.com",
                        "Device.Get",
                        "Device",
                        "sid-b",
                        "db-b",
                        "user-b",
                        "d-b",
                        200,
                        "{\"result\":[{\"id\":\"d-b\",\"typeName\":\"Device\"}],\"id\":1}"
                );

                ingest(index, security, workflow, entityStore, suggestions, authContextStore, recordA);
                ingest(index, security, workflow, entityStore, suggestions, authContextStore, recordB);

                authContextStore.setRoleForRecord(recordA.recordId(), RoleType.LOW_PRIV);
                authContextStore.setRoleForRecord(recordB.recordId(), RoleType.ADMIN);

                suggestions.recomputeSync();
                assertTrue(suggestions.snapshotSuggestions().isEmpty());
            }
        } finally {
            if (previous == null) {
                System.clearProperty(ALLOWED_HOSTS_PROPERTY);
            } else {
                System.setProperty(ALLOWED_HOSTS_PROPERTY, previous);
            }
        }
    }

    @Test
    void realTrafficDetectsSearchEnumMulticallAndMethodAccess() throws Exception {
        JsonRpcIndex index = new JsonRpcIndex();
        NoopLogging logging = new NoopLogging();
        AuthContextStore authContextStore = new AuthContextStore(objectMapper);

        try (SecurityAnalyzerService security = new SecurityAnalyzerService(objectMapper, index, authContextStore, logging);
             WorkflowGraphService workflow = new WorkflowGraphService(objectMapper, logging);
             EntityStoreService entityStore = new EntityStoreService(objectMapper, logging, authContextStore);
             AttackSuggestionService suggestions = new AttackSuggestionService(
                     objectMapper, index, security, workflow, entityStore, authContextStore, logging
             )) {

            // ── Real traffic #1: Get:DeviceStatusInfo with broad search (no entity-ID constraint)
            JsonRpcRecord lowDeviceStatus = createRawRecord(
                    "low-device-status",
                    "api.example.test",
                    "{\"method\":\"Get\",\"params\":{\"typeName\":\"DeviceStatusInfo\",\"search\":{\"isDeviceCommunicating\":true},\"resultsLimit\":1,\"credentials\":{\"database\":\"sample_db_01\",\"sessionId\":\"low-sid\",\"userName\":\"low@example.test\",\"date\":\"2026-04-16T17:48:58.507Z\"}}}",
                    200,
                    "{\"result\":[{\"id\":\"a1\",\"typeName\":\"DeviceStatusInfo\",\"device\":{\"id\":\"b1\"},\"isDeviceCommunicating\":true}],\"id\":1}"
            );

            // ── Real traffic #2: ExecuteMultiCall with write sub-call (Add:Audit + GetDashboardItems)
            JsonRpcRecord lowMultiCall = createRawRecord(
                    "low-multicall",
                    "api.example.test",
                    "{\"method\":\"ExecuteMultiCall\",\"params\":{\"calls\":[{\"method\":\"Add\",\"params\":{\"typeName\":\"Audit\",\"entity\":{\"name\":\"DashboardView\"}}},{\"method\":\"GetDashboardItems\",\"params\":{}}],\"credentials\":{\"database\":\"sample_db_01\",\"sessionId\":\"low-sid\",\"userName\":\"low@example.test\",\"date\":\"2026-04-16T17:48:58.507Z\"}}}",
                    200,
                    "{\"result\":[[\"audit-1\"],[]],\"id\":3}"
            );

            // ── Real traffic #3: GetReportSecurityIdentifiers (security-sensitive method)
            // Once as LOW_PRIV
            JsonRpcRecord lowSecurity = createRawRecord(
                    "low-security-ids",
                    "api.example.test",
                    "{\"method\":\"GetReportSecurityIdentifiers\",\"params\":{\"credentials\":{\"database\":\"sample_db_01\",\"sessionId\":\"low-sid\",\"userName\":\"low@example.test\",\"date\":\"2026-04-16T17:48:58.507Z\"}}}",
                    200,
                    "{\"result\":[{\"id\":\"sec-1\",\"name\":\"AllDevices\"}],\"id\":4}"
            );
            // Once as ADMIN (different session)
            JsonRpcRecord adminSecurity = createRawRecord(
                    "admin-security-ids",
                    "api.example.test",
                    "{\"method\":\"GetReportSecurityIdentifiers\",\"params\":{\"credentials\":{\"database\":\"sample_db_01\",\"sessionId\":\"admin-sid\",\"userName\":\"admin@example.test\",\"date\":\"2026-04-16T17:48:58.507Z\"}}}",
                    200,
                    "{\"result\":[{\"id\":\"sec-1\",\"name\":\"AllDevices\"},{\"id\":\"sec-2\",\"name\":\"AdminOnly\"}],\"id\":5}"
            );

            // Ingest all records
            ingest(index, security, workflow, entityStore, suggestions, authContextStore, lowDeviceStatus);
            ingest(index, security, workflow, entityStore, suggestions, authContextStore, lowMultiCall);
            ingest(index, security, workflow, entityStore, suggestions, authContextStore, lowSecurity);
            ingest(index, security, workflow, entityStore, suggestions, authContextStore, adminSecurity);

            // Tag roles
            authContextStore.setRoleForRecord(lowDeviceStatus.recordId(), RoleType.LOW_PRIV);
            authContextStore.setRoleForRecord(lowMultiCall.recordId(), RoleType.LOW_PRIV);
            authContextStore.setRoleForRecord(lowSecurity.recordId(), RoleType.LOW_PRIV);
            authContextStore.setRoleForRecord(adminSecurity.recordId(), RoleType.ADMIN);

            suggestions.recomputeSync();
            List<AttackSuggestion> rows = suggestions.snapshotSuggestions();
            assertFalse(rows.isEmpty(), "Expected findings from real traffic patterns");

            Set<String> types = rows.stream().map(AttackSuggestion::findingType).collect(Collectors.toSet());

            // SEARCH_ENUM: Get:DeviceStatusInfo with {isDeviceCommunicating:true} should fire
            assertTrue(types.contains("SEARCH_ENUM"),
                    "SEARCH_ENUM should fire for Get:DeviceStatusInfo with broad search. Found types: " + types);

            // METHOD_ACCESS: GetReportSecurityIdentifiers seen by both ADMIN and LOW_PRIV
            assertTrue(types.contains("METHOD_ACCESS"),
                    "METHOD_ACCESS should fire for GetReportSecurityIdentifiers. Found types: " + types);

            // MULTICALL_CHAIN: ExecuteMultiCall with Add (write) + GetDashboardItems (read)
            assertTrue(types.contains("MULTICALL_CHAIN"),
                    "MULTICALL_CHAIN should fire for ExecuteMultiCall with write sub-call. Found types: " + types);
        }
    }

    private void ingest(
            JsonRpcIndex index,
            SecurityAnalyzerService security,
            WorkflowGraphService workflow,
            EntityStoreService entityStore,
            AttackSuggestionService suggestions,
            AuthContextStore authContextStore,
            JsonRpcRecord record
    ) throws Exception {
        JsonRpcNormalizedRecord normalized = parser.normalize(record);
        AuthContextStore.AuthContext context = authContextStore.observeRecord(record, normalized.methodName());
        index.addRecord(normalized, record, context.contextKey());
        security.ingestRecordSync(record, normalized);
        workflow.ingestRecordSync(record, normalized);
        entityStore.ingestRecordSync(record, normalized);
        suggestions.ingestRecordAsync(record, normalized, false);
    }

    private JsonRpcRecord createStandardRecord(
            String recordIdSeed,
            String host,
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

        return createRawRecord(recordIdSeed, host, requestBody, responseStatus, responseBody);
    }

    private JsonRpcRecord createRawRecord(
            String recordIdSeed,
            String host,
            String requestBody,
            Integer responseStatus,
            String responseBody
    ) {
        List<String> headers = List.of(
                "Host: " + host,
                "Content-Type: application/json"
        );

        String rawRequest = "POST /apiv1 HTTP/1.1\r\n"
                + String.join("\r\n", headers)
                + "\r\n\r\n"
                + requestBody;

        JsonRpcRecord.RequestData requestData = JsonRpcRecord.RequestData.fromCaptured(
                "https://" + host + "/apiv1",
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
                "rec-" + recordIdSeed + "-" + Instant.now().toEpochMilli(),
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
