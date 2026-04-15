import burp.api.montoya.logging.Logging;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AttackSuggestionServiceTest {
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final JsonRpcParser parser = new JsonRpcParser(objectMapper, 128);

    @Test
    void suggestionAssertionsAreBehaviorBasedAndStable() throws Exception {
        JsonRpcIndex index = new JsonRpcIndex();
        NoopLogging logging = new NoopLogging();
        AuthContextStore authContextStore = new AuthContextStore(objectMapper);

        try (SecurityAnalyzerService security = new SecurityAnalyzerService(objectMapper, index, authContextStore, logging);
             WorkflowGraphService workflow = new WorkflowGraphService(objectMapper, logging);
             EntityStoreService entityStore = new EntityStoreService(objectMapper, logging);
             AttackSuggestionService suggestions = new AttackSuggestionService(
                     objectMapper,
                     index,
                     security,
                     workflow,
                     entityStore,
                     authContextStore,
                     logging
             )) {

            Scenario scenario = seedAllowedHostScenario(index, security, workflow, entityStore, suggestions, authContextStore);
            List<AttackSuggestion> rows = scenario.suggestions();

            assertFalse(rows.isEmpty(), "Expected non-empty suggestions for allowed MyGeotab host scenario");

            assertTrue(hasFamily(rows, "cross-tenant"), "Expected at least one cross-tenant/cross-database suggestion");
            assertTrue(hasFamily(rows, "auth"), "Expected at least one authorization-focused suggestion");
            assertTrue(hasFamily(rows, "privilege"), "Expected at least one privilege escalation/replay suggestion");
            assertTrue(hasFamily(rows, "batch"), "Expected at least one batch/multicall suggestion");
            assertTrue(hasFamily(rows, "notification"), "Expected at least one notification-mode suggestion");
            assertTrue(hasFamily(rows, "param-mutation"), "Expected at least one parameter mutation suggestion");

            for (AttackSuggestion suggestion : rows) {
                assertNotNull(suggestion.category());
                assertFalse(suggestion.category().isBlank());

                assertNotNull(suggestion.primaryMethod());
                assertFalse(suggestion.primaryMethod().isBlank());

                assertNotNull(suggestion.host());
                assertFalse(suggestion.host().isBlank());

                assertNotNull(suggestion.repeaterRequest());
                assertFalse(suggestion.repeaterRequest().isBlank());

                assertTrue(suggestion.confidenceScore() > 0, "confidenceScore must be > 0");
                assertTrue(suggestion.effectivenessScore() > 0, "effectivenessScore must be > 0");
            }
        }
    }

    @Test
    void mutationSuggestionsModifyRealCapturedRequestAndPreserveContext() throws Exception {
        JsonRpcIndex index = new JsonRpcIndex();
        NoopLogging logging = new NoopLogging();
        AuthContextStore authContextStore = new AuthContextStore(objectMapper);

        try (SecurityAnalyzerService security = new SecurityAnalyzerService(objectMapper, index, authContextStore, logging);
             WorkflowGraphService workflow = new WorkflowGraphService(objectMapper, logging);
             EntityStoreService entityStore = new EntityStoreService(objectMapper, logging);
             AttackSuggestionService suggestions = new AttackSuggestionService(
                     objectMapper,
                     index,
                     security,
                     workflow,
                     entityStore,
                     authContextStore,
                     logging
             )) {

            Scenario scenario = seedAllowedHostScenario(index, security, workflow, entityStore, suggestions, authContextStore);

            Set<String> capturedRawRequests = new HashSet<>();
            for (JsonRpcRecord record : scenario.records()) {
                capturedRawRequests.add(record.request().rawHttpText());
            }

            Optional<AttackSuggestion> mutatedSuggestion = scenario.suggestions().stream()
                    .filter(s -> s.repeaterRequest() != null && !s.repeaterRequest().isBlank())
                    .filter(s -> !capturedRawRequests.contains(s.repeaterRequest()))
                    .findFirst();

            assertTrue(mutatedSuggestion.isPresent(), "Expected at least one suggestion with a mutated captured request");

            ParsedHttpRequest mutated = parseRequest(mutatedSuggestion.get().repeaterRequest());
            JsonNode mutatedBody = objectMapper.readTree(mutated.body());
            String mutatedFingerprint = methodFingerprint(mutatedBody);

            Optional<ParsedHttpRequest> sourceOptional = scenario.records().stream()
                    .map(record -> parseRequest(record.request().rawHttpText()))
                    .filter(source -> Objects.equals(source.requestLine(), mutated.requestLine()))
                    .filter(source -> Objects.equals(source.header("host"), mutated.header("host")))
                    .filter(source -> Objects.equals(source.header("cookie"), mutated.header("cookie")))
                    .filter(source -> Objects.equals(source.header("authorization"), mutated.header("authorization")))
                    .filter(source -> {
                        try {
                            return methodFingerprint(objectMapper.readTree(source.body())).equals(mutatedFingerprint);
                        } catch (Exception ignored) {
                            return false;
                        }
                    })
                    .findFirst();

            assertTrue(sourceOptional.isPresent(), "Expected mutation to be based on a real captured request context");

            ParsedHttpRequest source = sourceOptional.get();
            assertEquals(source.requestLine(), mutated.requestLine(), "Request line must be preserved");
            assertEquals(source.header("host"), mutated.header("host"), "Host header must be preserved");
            assertEquals(source.header("cookie"), mutated.header("cookie"), "Cookie header must be preserved");
            assertEquals(source.header("authorization"), mutated.header("authorization"), "Authorization header must be preserved");

            JsonNode sourceBody = objectMapper.readTree(source.body());

            Set<String> diffPaths = new LinkedHashSet<>();
            collectDiffPaths(sourceBody, mutatedBody, "$", diffPaths);

            assertFalse(diffPaths.isEmpty(), "Expected JSON body differences in mutated suggestion");
            assertTrue(diffPaths.stream().allMatch(this::isTargetedPath),
                    "Expected only targeted JSON fields to change, but got: " + diffPaths);

            if (sourceBody.isObject() && mutatedBody.isObject()) {
                assertEquals(sourceBody.path("method").asText(), mutatedBody.path("method").asText(),
                        "Top-level method must remain unchanged");
            }
        }
    }

    @Test
    void outOfScopeHostsProduceNoSuggestions() throws Exception {
        JsonRpcIndex index = new JsonRpcIndex();
        NoopLogging logging = new NoopLogging();
        AuthContextStore authContextStore = new AuthContextStore(objectMapper);

        try (SecurityAnalyzerService security = new SecurityAnalyzerService(objectMapper, index, authContextStore, logging);
             WorkflowGraphService workflow = new WorkflowGraphService(objectMapper, logging);
             EntityStoreService entityStore = new EntityStoreService(objectMapper, logging);
             AttackSuggestionService suggestions = new AttackSuggestionService(
                     objectMapper,
                     index,
                     security,
                     workflow,
                     entityStore,
                     authContextStore,
                     logging
             )) {

            JsonRpcRecord recordA = createRecord(
                    "out-scope-a",
                    "example.com",
                    List.of("Cookie: sessionId=sid-a", "Authorization: Bearer token-a"),
                    """
                    {"jsonrpc":"2.0","method":"Device.Set","params":{"credentials":{"database":"db-a","sessionId":"sid-a","userName":"user-a"},"entity":{"deviceId":"d-a"}},"id":"a1"}
                    """.trim(),
                    200,
                    """
                    {"result":{"deviceId":"d-a","tenantId":"tenant-a"},"id":"a1"}
                    """.trim()
            );

            JsonRpcRecord recordB = createRecord(
                    "out-scope-b",
                    "api.example.com",
                    List.of("Cookie: sessionId=sid-b", "Authorization: Bearer token-b"),
                    """
                    {"jsonrpc":"2.0","method":"Device.Set","params":{"credentials":{"database":"db-b","sessionId":"sid-b","userName":"user-b"},"entity":{"deviceId":"d-b"}},"id":"b1"}
                    """.trim(),
                    200,
                    """
                    {"result":{"deviceId":"d-b","tenantId":"tenant-b"},"id":"b1"}
                    """.trim()
            );

            ingest(index, security, workflow, entityStore, suggestions, recordA);
            ingest(index, security, workflow, entityStore, suggestions, recordB);

            authContextStore.setRoleForRecord(recordA.recordId(), RoleType.LOW_PRIV);
            authContextStore.setRoleForRecord(recordB.recordId(), RoleType.ADMIN);

            suggestions.recomputeSync();

            List<AttackSuggestion> rows = suggestions.snapshotSuggestions();
            assertTrue(rows.isEmpty(), "Out-of-scope hosts must not produce suggestions");
        }
    }

    @Test
    void singleBatchAndNotificationJsonRpcRequestsAreHandled() throws Exception {
        JsonRpcIndex index = new JsonRpcIndex();
        NoopLogging logging = new NoopLogging();
        AuthContextStore authContextStore = new AuthContextStore(objectMapper);

        try (SecurityAnalyzerService security = new SecurityAnalyzerService(objectMapper, index, authContextStore, logging);
             WorkflowGraphService workflow = new WorkflowGraphService(objectMapper, logging);
             EntityStoreService entityStore = new EntityStoreService(objectMapper, logging);
             AttackSuggestionService suggestions = new AttackSuggestionService(
                     objectMapper,
                     index,
                     security,
                     workflow,
                     entityStore,
                     authContextStore,
                     logging
             )) {

            JsonRpcRecord single = createRecord(
                    "single",
                    "bugcrowd6.geotab.com",
                    List.of("Cookie: sessionId=single-sid", "Authorization: Bearer single-token"),
                    """
                    {"jsonrpc":"2.0","method":"Device.Get","params":{"credentials":{"database":"db-single","sessionId":"single-sid","userName":"single.user"},"search":{"deviceId":"d-single"}},"id":"single-1"}
                    """.trim(),
                    200,
                    """
                    {"result":{"deviceId":"d-single","tenantId":"tenant-single"},"id":"single-1"}
                    """.trim()
            );

            JsonRpcRecord batch = createRecord(
                    "batch",
                    "bugcrowd6.geotab.com",
                    List.of("Cookie: sessionId=single-sid", "Authorization: Bearer single-token"),
                    """
                    [{"jsonrpc":"2.0","method":"ExecuteMultiCall","params":{"credentials":{"database":"db-single","sessionId":"single-sid","userName":"single.user"},"calls":[{"method":"Device.Get","params":{"search":{"deviceId":"d-single"}}}]},"id":"batch-1"}]
                    """.trim(),
                    200,
                    """
                    [{"result":[{"deviceId":"d-single"}],"id":"batch-1"}]
                    """.trim()
            );

            JsonRpcRecord notification = createRecord(
                    "notification",
                    "bugcrowd6.geotab.com",
                    List.of("Cookie: sessionId=single-sid", "Authorization: Bearer single-token"),
                    """
                    {"jsonrpc":"2.0","method":"Device.Get","params":{"credentials":{"database":"db-single","sessionId":"single-sid","userName":"single.user"},"search":{"deviceId":"d-single"}}}
                    """.trim(),
                    200,
                    """
                    {"result":{"deviceId":"d-single"}}
                    """.trim()
            );

            JsonRpcNormalizedRecord singleNorm = parser.normalize(single);
            JsonRpcNormalizedRecord batchNorm = parser.normalize(batch);
            JsonRpcNormalizedRecord notificationNorm = parser.normalize(notification);

            assertFalse(singleNorm.batchRequest());
            assertTrue(batchNorm.batchRequest());
            assertTrue(notificationNorm.notificationRequest());

            ingest(index, security, workflow, entityStore, suggestions, single, singleNorm);
            ingest(index, security, workflow, entityStore, suggestions, batch, batchNorm);
            ingest(index, security, workflow, entityStore, suggestions, notification, notificationNorm);

            authContextStore.setRoleForRecord(single.recordId(), RoleType.LOW_PRIV);

            suggestions.recomputeSync();
            assertFalse(suggestions.snapshotSuggestions().isEmpty(),
                    "Expected suggestions after processing single/batch/notification traffic");
        }
    }

    private Scenario seedAllowedHostScenario(
            JsonRpcIndex index,
            SecurityAnalyzerService security,
            WorkflowGraphService workflow,
            EntityStoreService entityStore,
            AttackSuggestionService suggestions,
            AuthContextStore authContextStore
    ) throws Exception {
        JsonRpcRecord lowPrivWrite = createRecord(
                "low-write",
                "bugcrowd5.geotab.com",
                List.of("Cookie: sessionId=sid-low", "Authorization: Bearer low-token"),
                """
                {"jsonrpc":"2.0","method":"Device.Set","params":{"credentials":{"database":"db-low","sessionId":"sid-low","userName":"low.user"},"entity":{"deviceId":"d-low-1","groupId":"g-low"}},"id":"set-low-1"}
                """.trim(),
                200,
                """
                {"result":{"deviceId":"d-low-1","tenantId":"tenant-low"},"id":"set-low-1"}
                """.trim()
        );

        JsonRpcRecord adminWrite = createRecord(
                "admin-write",
                "bugcrowd5.geotab.com",
                List.of("Cookie: sessionId=sid-admin", "Authorization: Bearer admin-token"),
                """
                {"jsonrpc":"2.0","method":"Device.Set","params":{"credentials":{"database":"db-admin","sessionId":"sid-admin","userName":"admin.user"},"entity":{"deviceId":"d-admin-9","groupId":"g-admin"}},"id":"set-admin-1"}
                """.trim(),
                200,
                """
                {"result":{"deviceId":"d-admin-9","tenantId":"tenant-admin","groupId":"g-admin"},"id":"set-admin-1"}
                """.trim()
        );

        JsonRpcRecord batchRequest = createRecord(
                "batch",
                "bugcrowd5.geotab.com",
                List.of("Cookie: sessionId=sid-low", "Authorization: Bearer low-token"),
                """
                [{"jsonrpc":"2.0","method":"ExecuteMultiCall","params":{"credentials":{"database":"db-low","sessionId":"sid-low","userName":"low.user"},"calls":[{"method":"Device.Get","params":{"search":{"deviceId":"d-admin-9"}}},{"method":"Device.Set","params":{"entity":{"deviceId":"d-admin-9"}}}]},"id":"batch-1"}]
                """.trim(),
                200,
                """
                [{"result":[{"deviceId":"d-admin-9","tenantId":"tenant-admin"}],"id":"batch-1"}]
                """.trim()
        );

        JsonRpcRecord positionalGet = createRecord(
                "positional",
                "bugcrowd5.geotab.com",
                List.of("Cookie: sessionId=sid-low", "Authorization: Bearer low-token"),
                """
                {"jsonrpc":"2.0","method":"Device.Get","params":["d-low-1",{"database":"db-low"}],"id":"get-pos-1"}
                """.trim(),
                200,
                """
                {"result":{"deviceId":"d-low-1","tenantId":"tenant-low"},"id":"get-pos-1"}
                """.trim()
        );

        JsonRpcRecord notificationGet = createRecord(
                "notification",
                "bugcrowd5.geotab.com",
                List.of("Cookie: sessionId=sid-low", "Authorization: Bearer low-token"),
                """
                {"jsonrpc":"2.0","method":"Device.Get","params":{"credentials":{"database":"db-low","sessionId":"sid-low","userName":"low.user"},"search":{"deviceId":"d-low-1"}}}
                """.trim(),
                200,
                """
                {"result":{"deviceId":"d-low-1","tenantId":"tenant-low"}}
                """.trim()
        );

        List<JsonRpcRecord> records = List.of(lowPrivWrite, adminWrite, batchRequest, positionalGet, notificationGet);
        for (JsonRpcRecord record : records) {
            ingest(index, security, workflow, entityStore, suggestions, record);
        }

        authContextStore.setRoleForRecord(adminWrite.recordId(), RoleType.ADMIN);
        authContextStore.setRoleForRecord(lowPrivWrite.recordId(), RoleType.LOW_PRIV);
        authContextStore.setRoleForRecord(batchRequest.recordId(), RoleType.LOW_PRIV);
        authContextStore.setRoleForRecord(positionalGet.recordId(), RoleType.LOW_PRIV);

        // Re-observe after role tagging so stored suggestion context reflects ADMIN/LOW_PRIV labels.
        suggestions.ingestRecordAsync(lowPrivWrite, parser.normalize(lowPrivWrite), false);
        suggestions.ingestRecordAsync(adminWrite, parser.normalize(adminWrite), false);
        suggestions.ingestRecordAsync(batchRequest, parser.normalize(batchRequest), false);
        suggestions.ingestRecordAsync(positionalGet, parser.normalize(positionalGet), false);
        suggestions.ingestRecordAsync(notificationGet, parser.normalize(notificationGet), false);

        suggestions.recomputeSync();
        return new Scenario(records, suggestions.snapshotSuggestions());
    }

    private void ingest(
            JsonRpcIndex index,
            SecurityAnalyzerService security,
            WorkflowGraphService workflow,
            EntityStoreService entityStore,
            AttackSuggestionService suggestions,
            JsonRpcRecord record
    ) throws Exception {
        JsonRpcNormalizedRecord normalized = parser.normalize(record);
        ingest(index, security, workflow, entityStore, suggestions, record, normalized);
    }

    private void ingest(
            JsonRpcIndex index,
            SecurityAnalyzerService security,
            WorkflowGraphService workflow,
            EntityStoreService entityStore,
            AttackSuggestionService suggestions,
            JsonRpcRecord record,
            JsonRpcNormalizedRecord normalized
    ) {
        index.addRecord(normalized, record);
        security.ingestRecordSync(record, normalized);
        workflow.ingestRecordSync(record, normalized);
        entityStore.ingestRecordSync(record, normalized);
        suggestions.ingestRecordAsync(record, normalized, false);
    }

    private JsonRpcRecord createRecord(
            String recordIdSeed,
            String host,
            List<String> extraHeaders,
            String requestBody,
            Integer responseStatus,
            String responseBody
    ) {
        List<String> headers = new ArrayList<>();
        headers.add("Host: " + host);
        headers.addAll(extraHeaders);
        headers.add("Content-Type: application/json");

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

    private boolean hasFamily(List<AttackSuggestion> suggestions, String family) {
        return suggestions.stream().anyMatch(suggestion -> matchesFamily(suggestion, family));
    }

    private boolean matchesFamily(AttackSuggestion suggestion, String family) {
        String corpus = (suggestion.category() + " " + suggestion.findingTitle() + " "
                + suggestion.attackPath() + " " + suggestion.observation() + " " + suggestion.whySuspicious())
                .toLowerCase(Locale.ROOT);

        return switch (family) {
            case "cross-tenant" -> corpus.contains("cross-tenant") || corpus.contains("cross-database");
            case "auth" -> corpus.contains("auth") || corpus.contains("authorization");
            case "privilege" -> corpus.contains("privilege");
            case "batch" -> corpus.contains("batch") || corpus.contains("multicall");
            case "notification" -> corpus.contains("notification");
            case "param-mutation" -> corpus.contains("named->")
                    || corpus.contains("positional->")
                    || corpus.contains("nested param")
                    || corpus.contains("param encoding");
            default -> false;
        };
    }

    private ParsedHttpRequest parseRequest(String rawRequest) {
        String normalized = rawRequest.contains("\\r\\n") && !rawRequest.contains("\r\n")
                ? rawRequest.replace("\\r\\n", "\r\n")
                : rawRequest;

        int split = normalized.indexOf("\r\n\r\n");
        int separatorLength = 4;
        if (split < 0) {
            split = normalized.indexOf("\n\n");
            separatorLength = 2;
        }

        String head = split >= 0 ? normalized.substring(0, split) : normalized;
        String body = split >= 0 ? normalized.substring(split + separatorLength) : "";

        String[] lines = head.split("\\r?\\n");
        String requestLine = lines.length > 0 ? lines[0] : "";

        Map<String, String> headers = new LinkedHashMap<>();
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i];
            int colon = line.indexOf(':');
            if (colon < 1) {
                continue;
            }
            String name = line.substring(0, colon).trim().toLowerCase(Locale.ROOT);
            String value = line.substring(colon + 1).trim();
            headers.put(name, value);
        }

        return new ParsedHttpRequest(requestLine, headers, body);
    }

    private void collectDiffPaths(JsonNode left, JsonNode right, String path, Set<String> out) {
        boolean leftMissing = left == null || left.isMissingNode();
        boolean rightMissing = right == null || right.isMissingNode();

        if (leftMissing && rightMissing) {
            return;
        }
        if (leftMissing || rightMissing) {
            out.add(path);
            return;
        }

        if (left.getNodeType() != right.getNodeType()) {
            out.add(path);
            return;
        }

        if (left.isValueNode()) {
            if (!left.equals(right)) {
                out.add(path);
            }
            return;
        }

        if (left.isObject()) {
            Set<String> keys = new LinkedHashSet<>();
            left.fieldNames().forEachRemaining(keys::add);
            right.fieldNames().forEachRemaining(keys::add);
            for (String key : keys) {
                collectDiffPaths(left.get(key), right.get(key), path + "." + key, out);
            }
            return;
        }

        if (left.isArray()) {
            int max = Math.max(left.size(), right.size());
            for (int i = 0; i < max; i++) {
                JsonNode leftChild = i < left.size() ? left.get(i) : null;
                JsonNode rightChild = i < right.size() ? right.get(i) : null;
                collectDiffPaths(leftChild, rightChild, path + "[" + i + "]", out);
            }
        }
    }

    private boolean isTargetedPath(String path) {
        if ("$.id".equals(path)) {
            return true;
        }
        if (path.startsWith("$.params")) {
            return true;
        }

        String normalized = path.replaceAll("\\[\\d+\\]", "[]");
        if ("$[].id".equals(normalized)) {
            return true;
        }
        return normalized.startsWith("$[].params") || normalized.contains(".params.");
    }

    private String methodFingerprint(JsonNode body) {
        if (body == null || body.isNull() || body.isMissingNode()) {
            return "";
        }

        if (body.isObject()) {
            return "obj:" + body.path("method").asText("");
        }

        if (body.isArray()) {
            List<String> methods = new ArrayList<>();
            for (JsonNode item : body) {
                if (item != null && item.isObject()) {
                    methods.add(item.path("method").asText(""));
                }
            }
            return "arr:" + String.join("|", methods);
        }

        return body.getNodeType().name().toLowerCase(Locale.ROOT);
    }

    private record ParsedHttpRequest(String requestLine, Map<String, String> headers, String body) {
        private String header(String name) {
            return headers.get(name.toLowerCase(Locale.ROOT));
        }
    }

    private record Scenario(List<JsonRpcRecord> records, List<AttackSuggestion> suggestions) {
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
