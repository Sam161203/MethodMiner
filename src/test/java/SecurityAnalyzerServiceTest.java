import burp.api.montoya.logging.Logging;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SecurityAnalyzerServiceTest {
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final JsonRpcParser parser = new JsonRpcParser(objectMapper, 64);

    @Test
    void flagsSensitiveMethodRiskAndIdentityExposure() throws Exception {
        JsonRpcIndex index = new JsonRpcIndex();
        AuthContextStore authContextStore = new AuthContextStore(objectMapper);
        try (SecurityAnalyzerService analyzer = new SecurityAnalyzerService(objectMapper, index, authContextStore, new NoopLogging())) {

            JsonRpcRecord record = createRecord(
                    "https://example.test/rpc",
                    "POST",
                    List.of("Host: example.test", "Cookie: sessionId=user123", "Authorization: Bearer token-value"),
                    "{\"jsonrpc\":\"2.0\",\"method\":\"admin.exportReport\",\"params\":{},\"id\":1}",
                    200,
                    "{\"result\":{\"tenantId\":\"acme\",\"ownerEmail\":\"owner@example.test\",\"roles\":[\"admin\"],\"internalUrl\":\"http://internal.api.local/reports\"},\"id\":1}"
            );

            JsonRpcNormalizedRecord normalized = parser.normalize(record);
            index.addRecord(normalized, record);
            analyzer.ingestRecordSync(record, normalized);

            List<SecurityFinding> findings = analyzer.snapshotFindings();
            assertFalse(findings.isEmpty());

            SecurityFinding riskFinding = findingByTrigger(findings, "method_risk");
            assertNotNull(riskFinding);
            assertTrue(riskFinding.riskScore() >= 60);

            SecurityFinding exposureFinding = findingByTrigger(findings, "tenant_identity_exposure");
            assertNotNull(exposureFinding);
        }
    }

    @Test
    void detectsSchemaDriftAndAuthContextBehaviorDifferences() throws Exception {
        JsonRpcIndex index = new JsonRpcIndex();
        AuthContextStore authContextStore = new AuthContextStore(objectMapper);
        try (SecurityAnalyzerService analyzer = new SecurityAnalyzerService(objectMapper, index, authContextStore, new NoopLogging())) {

            JsonRpcRecord first = createRecord(
                "https://example.test/rpc",
                "POST",
                List.of("Host: example.test", "Cookie: sessionId=user-alpha"),
                "{\"jsonrpc\":\"2.0\",\"method\":\"account.getProfile\",\"params\":{\"credentials\":{\"database\":\"db-alpha\",\"userName\":\"user-alpha\"},\"userId\":100},\"id\":1}",
                200,
                "{\"result\":{\"id\":100,\"role\":\"user\",\"permissions\":[\"read\"]},\"id\":1}"
            );

            JsonRpcRecord second = createRecord(
                "https://example.test/rpc",
                "POST",
                List.of("Host: example.test", "Cookie: sessionId=admin-omega"),
                "{\"jsonrpc\":\"2.0\",\"method\":\"account.getProfile\",\"params\":{\"credentials\":{\"database\":\"db-alpha\",\"userName\":\"admin-omega\"},\"userId\":100},\"id\":1}",
                403,
                "{\"error\":{\"code\":\"403\",\"message\":\"forbidden\",\"backendRoute\":\"/internal/admin/check\"},\"id\":1}"
            );

            JsonRpcNormalizedRecord firstNorm = parser.normalize(first);
            JsonRpcNormalizedRecord secondNorm = parser.normalize(second);

            index.addRecord(firstNorm, first);
            index.addRecord(secondNorm, second);

            analyzer.ingestRecordSync(first, firstNorm);
            analyzer.ingestRecordSync(second, secondNorm);

            authContextStore.setRoleForRecord(first.recordId(), RoleType.LOW_PRIV);
            authContextStore.setRoleForRecord(second.recordId(), RoleType.ADMIN);

            List<SecurityFinding> findings = analyzer.snapshotFindings();

            assertNotNull(findingByTrigger(findings, "schema_drift"));
            assertNotNull(findingByTrigger(findings, "auth_context_correlation"));

            ObjectNode export = analyzer.buildManualExportBundle("account.getProfile");
            ArrayNode samples = (ArrayNode) export.path("samples");
            assertTrue(samples.size() >= 1);

            ArrayNode variants = (ArrayNode) samples.get(samples.size() - 1)
                .path("request")
                .path("manualVariants");

            assertTrue(hasVariant(variants, "empty_params_variant"));
            assertTrue(hasVariant(variants, "null_params_variant"));
            assertTrue(hasVariant(variants, "removed_credentials_variant"));
            assertTrue(hasVariant(variants, "extra_harmless_field_variant"));
        }
    }

    private boolean hasVariant(ArrayNode variants, String name) {
        for (int i = 0; i < variants.size(); i++) {
            if (name.equals(variants.get(i).path("name").asText())) {
                return true;
            }
        }
        return false;
    }

    private SecurityFinding findingByTrigger(List<SecurityFinding> findings, String trigger) {
        for (SecurityFinding finding : findings) {
            if (trigger.equals(finding.trigger())) {
                return finding;
            }
        }
        return null;
    }

    private JsonRpcRecord createRecord(
            String url,
            String method,
            List<String> headers,
            String requestBody,
            Integer responseStatus,
            String responseBody
    ) {
        String rawRequest = method + " /rpc HTTP/1.1\\r\\n" + String.join("\\r\\n", headers) + "\\r\\n\\r\\n" + requestBody;

        JsonRpcRecord.RequestData requestData = JsonRpcRecord.RequestData.fromCaptured(
                url,
                method,
                headers,
                requestBody,
                requestBody.getBytes(StandardCharsets.UTF_8),
                rawRequest,
                rawRequest.getBytes(StandardCharsets.UTF_8)
        );

        JsonRpcRecord.ResponseData responseData = responseStatus == null
                ? JsonRpcRecord.ResponseData.missing()
                : JsonRpcRecord.ResponseData.fromCaptured(
                responseStatus,
                List.of("Content-Type: application/json"),
                responseBody,
                responseBody.getBytes(StandardCharsets.UTF_8),
                "HTTP/1.1 " + responseStatus + "\\r\\nContent-Type: application/json\\r\\n\\r\\n" + responseBody,
                ("HTTP/1.1 " + responseStatus + "\\r\\nContent-Type: application/json\\r\\n\\r\\n" + responseBody)
                        .getBytes(StandardCharsets.UTF_8)
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
